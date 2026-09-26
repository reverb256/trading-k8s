#!/usr/bin/env python3
"""App-manifest guard: catches the known bug classes in `helm/apps/*.yaml`.

1. Glued command flags: an argv element like "tools/foo.py --flag" (the flag
   belongs in its own element) -- python then treats the whole string as a
   filename.
2. Duplicate mapping keys in the values block (YAML last-wins silently ignored
   `hostNetwork: true` when a duplicate `false` followed).
3. ARM-FLAG DOCTRINE (2026-09-22; revised 2026-09-23 for CAPITAL-LADDER Q7+Q8).
   A manifest that sources the host `/work/data/exec.env` is one shell line away
   from arming something, because that file holds `EXEC_ARMED=1`,
   `EVMC_ALLOW_LIVE=1` and `FUEL_REFUEL_MODE=armed`:
     * `EXEC_ARMED` and `FUEL_REFUEL_MODE` must be stripped by EVERY consumer.
       `config/exec.yaml` already carries `armed: true`, so the SOL two-key
       `(EXEC_ARMED) AND (cfg.armed)` is one leaked variable away from arming a
       real send; `FUEL_REFUEL_MODE=armed` flips the refueler's default "off".
     * `EVMC_ALLOW_LIVE` is the RHC lane's first key.  Q7+Q8 (2026-09-23,
       `docs/CAPITAL-LADDER.md` §5) armed the RHC send path in EXACTLY ONE
       place -- the daemon's own manifest -- and there it must be an **explicit
       re-export**, never an accident of `set -a; . exec.env`.  Every other
       consumer must strip it.
   No manifest may pass any of the three names through `env:`.
4. SECRET-IN-GIT (2026-09-22): the halt-alert A2A peer credential is an env-only
   0600 FILE the job mounts and reads.  A manifest may name that file's path and
   nothing else -- no token value, and no path outside the mounted repo's data
   dir (git-ignored, rendered by `deploy/halt-alerts/provision-peer-env.py`).
5. JUP-KEY-REACHABILITY (2026-09-26): a job whose command shells out to the jup
   CLI must set `repoHomeMount: true`.  The CLI resolves its activeKey at RUN
   time as `$HOME/.config/jup/keys/<name>.json`, and on the host that file is a
   SYMLINK into the repo (`/home/j_kro/Work/trading/data/keys/live.json`).  HOME
   is `/home/j_kro` in every pod and the jup config dir is host-mounted at that
   same absolute path, so the symlink only resolves if the repo is ALSO visible
   at the host path -- `/work` alone leaves it dangling and the CLI dies with
   `Key "float" does not exist.` (trading-jup-perps-exec, 2026-09-26: every
   non-neutral regime tick failed before it could print its preview).

6. DEADLINE-VS-INTERNAL-TIMEOUT (2026-09-26): `activeDeadlineSeconds` counts from
   JOB creation, but the container only starts 9-22s later (measured on nexus),
   and a command that bounds its OWN work (`--tail N` / `--seconds N`) also spends
   its tool's internal timeout slack (30s: `wait_for(consume(seconds),
   timeout=seconds + 30)`, the line that prints the tool's own failure).
   `trading-rhc-grad-watch` ran `--tail 45` under `deadline: 75` -- EXACTLY the
   45+30 cap -- so one late pod start made Kubernetes SIGKILL the run
   (DeadlineExceeded, `trading-rhc-grad-watch-29840438`, 2026-09-26) before it
   could print `RHC-GRAD-FAIL`, and the failed job carried no log to diagnose.
   Every self-bounded command must keep START_LATENCY_HEADROOM seconds of slack
   over its own cap.

`--selftest` proves the rule in both directions offline (synthetic manifests)
and then scans the real app dir; it prints APP-CHECK-SELFTEST-OK.

Exit 0 = clean; non-zero with a report otherwise.
"""
import os
import re
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "helm" / "apps"
#: where the tools named by a manifest's `command:` live (override for testing)
TRADING_REPO = Path(os.environ.get("TRADING_REPO", "/home/j_kro/Work/trading"))
#: the in-repo path of the jup CLI, as spelled in the tool sources
JUP_CLI = "npm-global/bin/jup"
SOL_ARM_FLAGS = ("EXEC_ARMED", "FUEL_REFUEL_MODE")
RHC_ARM_FLAG = "EVMC_ALLOW_LIVE"
ARM_FLAGS = (*SOL_ARM_FLAGS, RHC_ARM_FLAG)
EXEC_ENV = "/work/data/exec.env"
#: the single manifest that owns the RHC lane's arming (Q7+Q8, 2026-09-23).
RHC_ARM_MANIFEST = "trading-daemon.yaml"
RHC_ARM_REEXPORT = re.compile(r"export\s+EVMC_ALLOW_LIVE=1\b")
#: rule 6: seconds of pod-start latency a self-bounded command must still fit
#: under its `deadline` (job creation -> container start measured at 9-22s on
#: nexus, rounded up; the pod in the 2026-09-26 grad-watch failure got 53s of a
#: 75s deadline)
START_LATENCY_HEADROOM = 30
#: rule 6 fallback: the tool's own `timeout=seconds + N` slack, when the tool
#: named by the command cannot be read (tools/rhc_grad_watch.py and
#: tools/feed_lane.py both use +30)
DEFAULT_TIMEOUT_SLACK = 30


def scan_text(name: str, text: str) -> list:
    """The three bug classes, for one manifest's text.  Returns problem strings."""
    problems = []
    for cmd in re.findall(r'command: (\[[^\]]*\])', text):
        # split the JSON-ish array into elements
        elems = re.findall(r'"((?:[^"\\]|\\.)*)"', cmd)
        # sh -c payloads are shell strings BY DESIGN -- skip them
        start = 3 if len(elems) >= 3 and elems[0] == "sh" and elems[1] == "-c" else 0
        for e in elems[start:]:
            if re.search(r"\.py [^-]", e) or re.search(r"\.py --", e):
                problems.append(f"{name}: glued command element: {e!r}")
    # duplicate keys in the embedded values block (indented simple mappings)
    vals = text.split("values: |", 1)
    if len(vals) == 2:
        keys = {}
        for line in vals[1].splitlines():
            m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*): ", line)
            if m:
                k = m.group(1)
                keys[k] = keys.get(k, 0) + 1
        for k, n in keys.items():
            if n > 1:
                problems.append(f"{name}: duplicate key {k!r} x{n}")
    # ARM-FLAG DOCTRINE -- both directions.
    if EXEC_ENV in text:
        for flag in SOL_ARM_FLAGS:
            if not re.search(rf"unset[^\n]*\b{flag}\b", text):
                problems.append(
                    f"{name}: sources {EXEC_ENV} but never unsets {flag} "
                    f"(a bare source arms live execution)")
        if name == RHC_ARM_MANIFEST:
            if not RHC_ARM_REEXPORT.search(text):
                problems.append(
                    f"{name}: owns the RHC arming (Q7+Q8) but never "
                    f"re-exports EVMC_ALLOW_LIVE=1 — the lane stays ACTIVE and "
                    f"cannot send")
        elif RHC_ARM_REEXPORT.search(text):
            problems.append(
                f"{name}: re-exports {RHC_ARM_FLAG}=1 but is not the RHC arm "
                f"owner ({RHC_ARM_MANIFEST}) - the arming lives in exactly one "
                f"manifest (Q7+Q8)")
        elif not re.search(rf"unset[^\n]*\b{RHC_ARM_FLAG}\b", text):
            problems.append(
                f"{name}: sources {EXEC_ENV} but never unsets {RHC_ARM_FLAG} "
                f"(a bare source arms the RHC live lane)")
    for flag in ARM_FLAGS:
        if re.search(rf"-\s*name:\s*{flag}\b", text):
            problems.append(f"{name}: passes {flag} into the container env")
    # SECRET-IN-GIT guard (2026-09-22): the halt-alert A2A peer credential is an
    # env-only 0600 FILE that the job mounts and reads. A manifest may name that
    # file's path and nothing else -- no token value, and no path outside the
    # mounted repo's data dir (which is git-ignored and rendered by
    # deploy/halt-alerts/provision-peer-env.py on the host).
    if "HALT_ALERTS_PEER_TOKEN" in text:
        problems.append(f"{name}: carries HALT_ALERTS_PEER_TOKEN -- a bearer "
                        f"token for the money-alert path must never be in git")
    for value in re.findall(r"-\s*name:\s*HALT_ALERTS_PEER_FILE\s*\n\s*value:\s*(\S+)",
                            text):
        if not value.strip('"').startswith("/work/data/"):
            problems.append(f"{name}: HALT_ALERTS_PEER_FILE={value!r} is outside "
                            f"/work/data/ -- the peer file must be the mounted, "
                            f"git-ignored 0600 file")
    # 5. JUP-KEY-REACHABILITY -- a jup-CLI caller needs the repo at its host path.
    for elem in sorted(set(re.findall(r'"([^"\s]*\.py)"', text))):
        tool = TRADING_REPO / elem
        if not tool.is_file():
            continue
        try:
            body = tool.read_text(errors="ignore")
        except OSError:
            continue
        if JUP_CLI in body and not re.search(r"^\s*repoHomeMount:\s*true\b", text, re.M):
            problems.append(
                f"{name}: runs {elem}, which calls the jup CLI, but does not set "
                f"repoHomeMount: true -- the CLI's activeKey is a symlink from "
                f"$HOME/.config/jup/keys/ into the repo, so the repo must be "
                f"mounted at {TRADING_REPO} inside the pod (else the CLI dies "
                f"with `Key \"float\" does not exist.`)")
    # 6. DEADLINE-VS-INTERNAL-TIMEOUT (2026-09-26) -- see the module docstring.
    # A command that bounds its own runtime needs a deadline that clears that
    # bound, its tool's own timeout slack, and the pod-start latency that
    # activeDeadlineSeconds silently eats (it counts from JOB creation).
    secs = None
    for flag in ("--tail", "--seconds"):
        m = re.search(rf'"{flag}",\s*"(\d+)"', text)
        if m:
            secs = int(m.group(1))
            break
    if secs is not None and len(vals) == 2:
        md = re.search(r"^\s*deadline:\s*(\d+)\s*$", vals[1], re.M)
        if md:
            deadline = int(md.group(1))
            slack = DEFAULT_TIMEOUT_SLACK
            tool_m = re.search(r'"(tools/[^"\s]*\.py)"', text)
            if tool_m and (TRADING_REPO / tool_m.group(1)).is_file():
                tm = re.search(r"timeout=\s*[\w.]+\s*\+\s*(\d+)",
                               (TRADING_REPO / tool_m.group(1)).read_text(errors="ignore"))
                if tm:
                    slack = int(tm.group(1))
            need = secs + slack + START_LATENCY_HEADROOM
            if deadline < need:
                problems.append(
                    f"{name}: deadline {deadline}s is under the {need}s this "
                    f"command needs (its own {secs}s bound + {slack}s tool timeout "
                    f"+ {START_LATENCY_HEADROOM}s pod-start latency) -- "
                    f"activeDeadlineSeconds counts from job creation, so a late pod "
                    f"start SIGKILLs the tool before it can print its own failure "
                    f"line (trading-rhc-grad-watch, 2026-09-26)")
    return problems


def selftest() -> int:
    """Both directions, offline, on synthetic manifests.  Exit 0 = the rule
    catches what it must catch and passes what it must pass."""
    fails = []

    def ck(cond, what):
        print(f"  {'ok  ' if cond else 'FAIL'} {what}")
        if not cond:
            fails.append(what)

    src = ("        command: [\"sh\", \"-c\", \"set -a; . /work/data/exec.env; "
           "set +a; unset EXEC_ARMED EVMC_ALLOW_LIVE FUEL_REFUEL_MODE; exec "
           "python -u /work/src/daemon.py\"]\n")
    ck(scan_text("some-job.yaml", src) == [],
       "a consumer that strips all three is clean")

    armed = ("        command: [\"sh\", \"-c\", \"set -a; . /work/data/exec.env; "
             "set +a; unset EXEC_ARMED FUEL_REFUEL_MODE; export "
             "EVMC_ALLOW_LIVE=1; exec python -u /work/src/daemon.py\"]\n")
    ck(scan_text("trading-daemon.yaml", armed) == [],
       "the RHC arm manifest (explicit re-export, SOL flags stripped) is clean")

    leak = ("        command: [\"sh\", \"-c\", \"set -a; . /work/data/exec.env; "
            "set +a; unset EVMC_ALLOW_LIVE FUEL_REFUEL_MODE; exec python -u "
            "/work/src/x.py\"]\n")
    got = scan_text("some-job.yaml", leak)
    ck(len(got) == 1 and "never unsets EXEC_ARMED" in got[0],
       "a leaked SOL arm flag is caught")

    silent = ("        command: [\"sh\", \"-c\", \"set -a; . /work/data/exec.env; "
              "set +a; unset EXEC_ARMED FUEL_REFUEL_MODE; exec python -u "
              "/work/src/daemon.py\"]\n")
    got = scan_text("trading-daemon.yaml", silent)
    ck(len(got) == 1 and "never re-exports EVMC_ALLOW_LIVE=1" in got[0],
       "the RHC arm manifest that forgot its re-export is caught (the lane would "
       "be ACTIVE and unable to send)")

    other = ("        command: [\"sh\", \"-c\", \"set -a; . /work/data/exec.env; "
             "set +a; unset EXEC_ARMED FUEL_REFUEL_MODE; export "
             "EVMC_ALLOW_LIVE=1; exec python -u /work/src/x.py\"]\n")
    got = scan_text("some-other-job.yaml", other)
    ck(len(got) == 1 and "is not the RHC arm owner" in got[0],
       "a NON-owner manifest may not arm the RHC lane (unset on one line, "
       "re-export on the next must not slip through)")

    quiet = ("        command: [\"sh\", \"-c\", \"set -a; . /work/data/exec.env; "
             "set +a; unset EXEC_ARMED FUEL_REFUEL_MODE; exec python -u "
             "/work/src/x.py\"]\n")
    got = scan_text("some-other-job.yaml", quiet)
    ck(len(got) == 1 and "never unsets EVMC_ALLOW_LIVE" in got[0],
       "a bare source with no RHC strip at all is caught")

    envpass = "        env:\n          - name: EXEC_ARMED\n            value: \"1\"\n"
    ck(any("passes EXEC_ARMED" in p for p in scan_text("x.yaml", envpass)),
       "an arm flag passed through `env:` is caught")

    peer = ("        env:\n          - name: HALT_ALERTS_PEER_FILE\n"
            "            value: \"/etc/provisioned-peer.env\"\n")
    ck(any("outside /work/data/" in p for p in scan_text("x.yaml", peer)),
       "a peer file outside the mounted data dir is caught")
    ok_peer = ("        env:\n          - name: HALT_ALERTS_PEER_FILE\n"
               "            value: \"/work/data/halt_peer.env\"\n")
    ck(scan_text("x.yaml", ok_peer) == [],
       "the mounted peer file path is allowed")
    tok = "        env:\n          - name: HALT_ALERTS_PEER_TOKEN\n            value: \"x\"\n"
    ck(any("must never be in git" in p for p in scan_text("x.yaml", tok)),
       "a peer bearer token in git is caught")

    glued = "        command: [\"python\", \"tools/a.py --flag\"]\n"
    ck(any("glued command element" in p for p in scan_text("x.yaml", glued)),
       "a glued argv element is still caught")
    dup = "        values: |\n          name: a\n          name: b\n"
    ck(any("duplicate key" in p for p in scan_text("x.yaml", dup)),
       "a duplicate mapping key is still caught")

    # JUP-KEY-REACHABILITY (2026-09-26), both directions. The synthetic manifests
    # name the REAL tool, so the check reads a real jup-CLI caller; if the repo is
    # not on this machine the two cases below are skipped, not silently passed.
    have_tool = (TRADING_REPO / "tools" / "jup_perps_exec.py").is_file()
    jup_cmd = '        command: ["python", "tools/jup_perps_exec.py", "--dry-run"]\n'
    ck(not have_tool or
       any("repoHomeMount" in p for p in scan_text("x.yaml", jup_cmd)),
       "a jup-CLI caller with no repoHomeMount is caught "
       "(trading-jup-perps-exec, 2026-09-26)")
    ck(scan_text("x.yaml", jup_cmd + "        repoHomeMount: true\n") == [],
       "the same caller WITH repoHomeMount: true is clean")
    ck(scan_text("x.yaml", '        command: ["python", "tools/curve_watch.py"]\n') == [],
       "a job that does not call the jup CLI needs no repoHomeMount")

    # 6. DEADLINE-VS-INTERNAL-TIMEOUT (2026-09-26), both directions. The synthetic
    # manifests name the REAL tool, so the check reads its real `+30` slack; if the
    # repo is not on this machine the 30s fallback applies and the cases below hold
    # either way (both are >= 105s of need at --tail 45).
    tight = ('        command: ["python", "tools/rhc_grad_watch.py", "--tail", "45"]\n'
             '        values: |\n          name: x\n          deadline: 75\n')
    ck(any("is under the" in p and "pod-start latency" in p
           for p in scan_text("x.yaml", tight)),
       "a deadline equal to the tool's own cap is caught "
       "(trading-rhc-grad-watch, 2026-09-26: DeadlineExceeded, no log)")
    ck(scan_text("x.yaml", tight.replace("deadline: 75", "deadline: 120")) == [],
       "the same job at deadline 120 is clean")
    ck(scan_text("x.yaml", tight.replace("deadline: 75", "deadline: 104")) != [],
       "one second under the need is still caught")
    unbounded = ('        command: ["python", "tools/curve_watch.py"]\n'
                 '        values: |\n          name: x\n          deadline: 30\n')
    ck(scan_text("x.yaml", unbounded) == [],
       "a job that bounds no work of its own is not judged on its deadline -- "
       "a short deadline is only a bug when the command sets its own bound")

    problems = []
    for p in sorted(APP_DIR.glob("*.yaml")):
        problems.extend(scan_text(p.name, p.read_text()))
    ck(not problems,
       f"the real app dir is clean ({len(list(APP_DIR.glob('*.yaml')))} manifests)")
    for pr in problems:
        print(f"    - {pr}")

    if fails:
        print("APP-CHECK-SELFTEST-FAIL")
        return 1
    print("APP-CHECK-SELFTEST-OK")
    return 0


def main() -> int:
    problems = []
    for p in sorted(APP_DIR.glob("*.yaml")):
        problems.extend(scan_text(p.name, p.read_text()))
    if problems:
        print("APP-CHECK-FAIL")
        print("\n".join(problems))
        return 1
    consumers = [p for p in APP_DIR.glob("*.yaml") if EXEC_ENV in p.read_text()]
    print(f"APP-CHECK-OK ({len(list(APP_DIR.glob('*.yaml')))} manifests, "
          f"{len(consumers)} exec.env consumers: SOL arm flags stripped, RHC key "
          f"explicitly re-exported in {RHC_ARM_MANIFEST} only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest() if "--selftest" in sys.argv else main())
