"""Screenshot regression oracle — diff baseline/ vs current/ PNGs.

Usage:
    python tools/screenshot_diff.py

Exit code 0 = no visual diff.
Exit code 1 = any diff, missing image, or new image without a baseline.
"""

import sys
from pathlib import Path
from PIL import Image, ImageChops

root = Path("tests/browser/screenshots")
base, cur = root / "baseline", root / "current"
fail = False
base_names = {p.name for p in base.glob("*.png")}
cur_names = {p.name for p in cur.glob("*.png")}

for name in sorted(base_names - cur_names):          # baseline image not re-captured
    print(f"MISSING from current/: {name}"); fail = True
for name in sorted(cur_names - base_names):          # new image with no baseline
    print(f"NEW (no baseline): {name}"); fail = True

for name in sorted(base_names & cur_names):
    a = Image.open(base / name).convert("RGB")
    c = Image.open(cur / name).convert("RGB")
    if a.size != c.size:
        print(f"SIZE CHANGED: {name} {a.size} -> {c.size}"); fail = True; continue
    bbox = ImageChops.difference(a, c).getbbox()
    if bbox is None:
        print(f"{name}: 0 changed px"); continue
    n = sum(1 for px in ImageChops.difference(a, c).getdata() if px != (0, 0, 0))
    print(f"{name}: {n} changed px  bbox={bbox}"); fail = True

print("FAIL — visual diff detected" if fail else "PASS — no visual diff")
sys.exit(1 if fail else 0)   # non-zero so CI / the gate actually catches regressions
