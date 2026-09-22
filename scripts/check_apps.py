#!/usr/bin/env python3
"""App-manifest guard: catches the two 2026-09-22 bug classes.

1. Glued command flags: an argv element like "tools/foo.py --flag" (the flag
   belongs in its own element) -- python then treats the whole string as a
   filename.
2. Duplicate mapping keys in the values block (YAML last-wins silently ignored
   `hostNetwork: true` when a duplicate `false` followed).

Exit 0 = clean; non-zero with a report otherwise.
"""
import re
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "helm" / "apps"
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

if problems:
    print("APP-CHECK-FAIL")
    print("\n".join(problems))
    sys.exit(1)
print(f"APP-CHECK-OK ({len(list(APP_DIR.glob('*.yaml')))} manifests)")
