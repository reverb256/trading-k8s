#!/usr/bin/env python3
"""Cutover env audit — diff the env each migrated ns=trading workload NEEDS
against the env it actually GETS.

Why it exists: the k3s cutover dropped environments repeatedly, and each one
looked like a local mistake while being the same class. The retired host units
gave their processes the host's paths and encrypted env; a pod only gets what
its manifest says. Three instances so far:
  * trading-reconcile-evm / -live (fixed): the job never sourced exec.env, so
    the live reconcile silently fell back to a KEYLESS public endpoint.
  * trading-daemon (fixed): the unit's EnvironmentFile=…/data/exec.env was not
    migrated, so ALCHEMY_KEY / EXEC_RPC_URL were missing and the EVM dryrun
    failed with EvmError("ALCHEMY_KEY not set").
  * trading-alerts: resolves its A2A peer from ~/.hermes/config.yaml, which is
    NOT mounted in the pod (`_peer()` -> FileNotFoundError). Currently masked
    because the still-enabled host trading-alerts.timer delivers instead and the
    cursor is now confirmed-delivery-only, so the pod fails closed.

How "needs" is derived (no guessing): the container argv is resolved to a repo
entrypoint, and the entrypoint's TRANSITIVE LOCAL IMPORTS (src/, tools/, mcp/)
are scanned for os.environ / os.getenv / getenv reads, plus `environ.get(CONST)`
via module constants and `{"NAME": os.environ[...]}` env maps. A module that
locates and loads data/exec.env itself is marked SELF-LOAD (immune). An argv that
shell-sources /work/data/exec.env is credited with that file's names.

Exit 0 always: this is a REPORT. Read the two sections at the end.

Usage:  python3 scripts/audit_env.py [--trading-repo /home/j_kro/Work/trading]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

KUBECONFIG = os.environ.get("KUBECONFIG", "/etc/rancher/k3s/k3s.yaml")
NAMESPACE = "trading"

# Env vars that live in data/exec.env. NAMES ONLY -- never print values.
EXEC_ENV_VARS = {"ALCHEMY_KEY", "EVMC_ALLOW_LIVE", "EVMC_RPC_URL", "EXEC_ARMED",
                 "EXEC_RPC_URL", "EXEC_RPC_URL_FALLBACK", "EXEC_RPC_URL_MAINNET",
                 "FUEL_REFUEL_MODE"}
EXEC_ENV_PATH = "/work/data/exec.env"

# Vars the container/os provides for free: reading them is not a manifest gap.
AMBIENT = {"HOME", "PATH", "PYTHONPATH", "LANG", "TZ", "USER", "PWD", "HOSTNAME",
           "TMPDIR", "PYTHONUNBUFFERED", "VIRTUAL_ENV", "VIRTUAL_ENV_PROMPT",
           "SSL_CERT_FILE", "SSL_CERT_DIR", "WEB_CONCURRENCY", "TERM", "SHELL",
           "LOGNAME", "XDG_RUNTIME_DIR", "COMP_WORDS", "COMP_CWORD",
           "PYTHON_DOTENV_DISABLED", "OMP_NUM_THREADS", "CUDA_VISIBLE_DEVICES",
           "NVIDIA_VISIBLE_DEVICES"}

GETENV_RE = re.compile(
    r"""(?:os\.)?(?:environ(?:\.get)?|getenv)\s*[\[\(]\s*["']([A-Z][A-Z0-9_]+)["']""")
GETENV_VAR_RE = re.compile(
    r"""(?:os\.)?(?:environ(?:\.get)?|getenv)\s*[\[\(]\s*([A-Z][A-Z0-9_]+)\b""")
CONST_RE = re.compile(r"""^([A-Z][A-Z0-9_]+)\s*=\s*["']([A-Z][A-Z0-9_]+)["']""", re.M)
ENVDICT_RE = re.compile(r"""["']([A-Z][A-Z0-9_]+)["']\s*:\s*(?:os\.)?(?:environ|getenv)""")
SELFLOAD_RE = re.compile(
    r"""["']exec\.env["'][\s\S]{0,400}?(?:environ\.update|environ\[|setdefault|load_dotenv)""")

# What the retired host units sourced (repo systemd/ + ~/.config/systemd/user).
# Only these ever had an EnvironmentFile; a workload not listed here never had
# a host env file to lose.
RETIRED_UNIT_ENV = {
    "trading-daemon": EXEC_ENV_PATH,
    "trading-reconcile-live": EXEC_ENV_PATH,
    "trading-reconcile-evm": EXEC_ENV_PATH,
    "rhc-canary-watch": EXEC_ENV_PATH,      # never migrated; still a host unit
}


def kubectl(args, ns=NAMESPACE):
    env = {"KUBECONFIG": KUBECONFIG, "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    out = subprocess.run(["kubectl", "-n", ns, *args], capture_output=True,
                         text=True, env=env)
    if out.returncode != 0:
        sys.exit(f"kubectl failed: {out.stderr.strip()}")
    return json.loads(out.stdout)


def module_index(repo: Path):
    idx = {}
    for d in ("src", "tools", "mcp"):
        for p in (repo / d).glob("*.py"):
            idx.setdefault(p.stem, p)
    return idx


def imports_of(text: str, mods: dict) -> set:
    names = set()
    for m in re.finditer(r"^\s*from\s+([A-Za-z_]\w*)\s+import\s+([^\n#]+)", text, re.M):
        names.add(m.group(1))
        for part in m.group(2).split(","):
            part = part.strip().split(" as ")[0].strip()
            if part:
                names.add(part)
    for m in re.finditer(r"^\s*import\s+([^\n#]+)", text, re.M):
        for part in m.group(1).split(","):
            part = part.strip().split(" as ")[0].strip().split(".")[0]
            if part:
                names.add(part)
    return {n for n in names if n in mods}


def closure(repo: Path, entry: str, mods: dict):
    seen, stack, envs, paths, self_load = set(), [entry], set(), [], False
    while stack:
        n = stack.pop()
        if n in seen or n not in mods:
            continue
        seen.add(n)
        p = mods[n]
        paths.append(str(p.relative_to(repo)))
        t = p.read_text(errors="replace")
        envs |= set(GETENV_RE.findall(t)) | set(ENVDICT_RE.findall(t))
        consts = dict(CONST_RE.findall(t))
        for m in GETENV_VAR_RE.finditer(t):
            if m.group(1) in consts:
                envs.add(consts[m.group(1)])
        self_load = self_load or bool(SELFLOAD_RE.search(t))
        stack.extend(imports_of(t, mods))
    return envs, self_load, paths


PY_RE = re.compile(r"([A-Za-z0-9_./-]*[A-Za-z0-9_]\.py)\b")


def entrypoints(argv):
    """Module stems named by the argv. Every `.py` occurrence counts, including
    one inside an `sh -c` payload (a shell source line can itself contain a
    path to exec.env, so matching on "ends with .py" is not enough)."""
    out = []
    for tok in argv:
        for m in PY_RE.finditer(str(tok)):
            stem = m.group(1).rsplit("/", 1)[-1][:-3]
            if stem not in out:
                out.append(stem)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trading-repo", default=os.environ.get(
        "TRADING_REPO", "/home/j_kro/Work/trading"))
    args = ap.parse_args()
    repo = Path(args.trading_repo)
    if not (repo / "src").is_dir():
        sys.exit(f"trading repo not found at {repo} (--trading-repo)")
    mods = module_index(repo)

    rows, problems = [], []
    for it in kubectl(["get", "deploy,cronjob", "-o", "json"])["items"]:
        kind, name = it["kind"], it["metadata"]["name"]
        spec = (it["spec"]["template"]["spec"] if kind == "Deployment"
                else it["spec"]["jobTemplate"]["spec"]["template"]["spec"])
        for c in spec.get("containers", []):
            argv = [str(x) for x in (c.get("command") or []) + (c.get("args") or [])]
            granted = {e["name"] for e in (c.get("env") or [])} | {"HOME"}
            eps = entrypoints(argv)
            needed, self_load = set(), False
            for e in eps:
                n, sl, _ = closure(repo, e, mods)
                needed |= n
                self_load = self_load or sl
            sources = EXEC_ENV_PATH in " ".join(argv)
            runtime = set(EXEC_ENV_VARS) if sources else set()
            unmet = sorted(needed - granted - runtime - AMBIENT)
            req = sorted((needed & EXEC_ENV_VARS) - granted - runtime)
            rows.append(dict(kind=kind, name=name, eps=",".join(eps),
                             granted=sorted(granted), unmet=unmet,
                             exec_required=req, self_load=self_load,
                             sources=sources))
            if req and not self_load:
                problems.append((name, req, self_load))

    print(f"=== {len(rows)} workloads in ns {NAMESPACE} ===")
    print(f"{'WORKLOAD':<28} {'ENTRY':<20} {'SELF-LOAD':<10} "
          f"{'SOURCES exec.env':<17} UNMET (need - granted)")
    print("-" * 118)
    for r in sorted(rows, key=lambda r: r["name"]):
        print(f"{r['name']:<28} {r['eps']:<20} {str(r['self_load']):<10} "
              f"{str(r['sources']):<17} {','.join(r['unmet']) or '-'}")

    print()
    print("=== exec.env vars REQUIRED but NOT supplied (a real env loss) ===")
    if not problems:
        print("  none")
    for n, req, sl in problems:
        print(f"  * {n}: needs {','.join(req)} — self-loads={sl}")

    print()
    print("=== exec.env consumers (each must be arm-stripped) ===")
    for r in sorted(rows, key=lambda r: r["name"]):
        if r["sources"] or r["self_load"]:
            print(f"  * {r['name']}: "
                  f"{'shell-sources' if r['sources'] else 'self-loads exec.env'}"
                  f"{' (SELF-LOAD = immune to the env loss)' if r['self_load'] else ''}")

    print()
    print("=== workloads with a retired host EnvironmentFile but no exec.env here ===")
    lost = [n for n, f in RETIRED_UNIT_ENV.items()
            if f == EXEC_ENV_PATH
            and any(r["name"] == n and not r["sources"] and not r["self_load"]
                    for r in rows)]
    print("  " + (", ".join(lost) if lost else "none (all exec.env consumers covered)"))
    print()
    print("NOTE: an unmet name with a code default (os.environ.get(NAME, <default>)) "
          "or a config fallback is NOT a defect and is listed above only for "
          "completeness — verify before calling it a loss.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
