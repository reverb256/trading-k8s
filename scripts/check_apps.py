#!/usr/bin/env python3
"""App-manifest guard: catches the three known bug classes.

1. Glued command flags: an argv element like "tools/foo.py --flag" (the flag
   belongs in its own element) -- python then treats the whole string as a
   filename.
2. Duplicate mapping keys in the values block (YAML last-wins silently ignored
   `hostNetwork: true` when a duplicate `false` followed).
3. ARM-FLAG LEAK (2026-09-22): a manifest that sources the host
   /work/data/exec.env must strip EXEC_ARMED / EVMC_ALLOW_LIVE /
   FUEL_REFUEL_MODE in the same shell payload, and no manifest may pass those
   names through `env:`. That file holds EXEC_ARMED=1, EVMC_ALLOW_LIVE=1 and
   FUEL_REFUEL_MODE=armed, and config/exec.yaml already carries `armed: true`,
   so the two-key arming rule -- (EXEC_ARMED truthy) AND (cfg.armed) in
   src/exec_bridge.py -- is ONE key away from the moment a pod starts. The k3s
   cutover dropped the daemon's exec.env and the fix must restore the RPC/key
   env WITHOUT arming; a blanket `set -a; . exec.env` arms the devnet send path,
   hands the RHC live lane one of its two keys (EVMC_ALLOW_LIVE) and flips the
   refueler's default "off" to armed (FUEL_REFUEL_MODE).

Exit 0 = clean; non-zero with a report otherwise.
"""
import re
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "helm" / "apps"
ARM_FLAGS = ("EXEC_ARMED", "EVMC_ALLOW_LIVE", "FUEL_REFUEL_MODE")
EXEC_ENV = "/work/data/exec.env"
problems = []

for p in sorted(APP_DIR.glob("*.yaml")):
    text = p.read_text()
    for cmd in re.findall(r'command: (\[[^\]]*\])', text):
        # split the JSON-ish array into elements
        elems = re.findall(r'"((?:[^"\\]|\\.)*)"', cmd)
        # sh -c payloads are shell strings BY DESIGN -- skip them
        start = 3 if len(elems) >= 3 and elems[0] == "sh" and elems[1] == "-c" else 0
        for e in elems[start:]:
            if re.search(r"\.py [^-]", e) or re.search(r"\.py --", e):
                problems.append(f"{p.name}: glued command element: {e!r}")
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
                problems.append(f"{p.name}: duplicate key {k!r} x{n}")
    # ARM-FLAG LEAK -- both directions.
    if EXEC_ENV in text:
        for flag in ARM_FLAGS:
            if not re.search(rf"unset[^\n]*\b{flag}\b", text):
                problems.append(
                    f"{p.name}: sources {EXEC_ENV} but never unsets {flag} "
                    f"(a bare source arms live execution)")
    for flag in ARM_FLAGS:
        if re.search(rf"-\s*name:\s*{flag}\b", text):
            problems.append(f"{p.name}: passes {flag} into the container env")
    # SECRET-IN-GIT guard (2026-09-22): the halt-alert A2A peer credential is an
    # env-only 0600 FILE that the job mounts and reads. A manifest may name that
    # file's path and nothing else -- no token value, and no path outside the
    # mounted repo's data dir (which is git-ignored and rendered by
    # deploy/halt-alerts/provision-peer-env.py on the host).
    if "HALT_ALERTS_PEER_TOKEN" in text:
        problems.append(f"{p.name}: carries HALT_ALERTS_PEER_TOKEN -- a bearer "
                        f"token for the money-alert path must never be in git")
    for value in re.findall(r"-\s*name:\s*HALT_ALERTS_PEER_FILE\s*\n\s*value:\s*(\S+)",
                            text):
        if not value.strip('"').startswith("/work/data/"):
            problems.append(f"{p.name}: HALT_ALERTS_PEER_FILE={value!r} is outside "
                            f"/work/data/ -- the peer file must be the mounted, "
                            f"git-ignored 0600 file")

if problems:
    print("APP-CHECK-FAIL")
    print("\n".join(problems))
    sys.exit(1)
print(f"APP-CHECK-OK ({len(list(APP_DIR.glob('*.yaml')))} manifests, "
      f"{len([p for p in APP_DIR.glob('*.yaml') if EXEC_ENV in p.read_text()])} "
      "exec.env consumers all arm-stripped)")
