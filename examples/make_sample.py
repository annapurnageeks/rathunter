"""Build the sample report (docs/index.html) from the simulated infected Mac in tests/simulated.py."""
import sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
import rathunter
from simulated import SimulatedMac

with tempfile.TemporaryDirectory() as tmp:
    mac = SimulatedMac(tmp, infected=True)
    result = rathunter.scan(mac)
result["sample"] = True
result["system"] = "macOS 27.1 (simulated)"
for f in result["findings"]:   # the temp folder name is noise; show the paths the way they'd look on a real Mac
    if f.get("where"):
        f["where"] = f["where"].replace(tmp, "")
rathunter.render_html(result, ROOT / "docs" / "index.html")
print("wrote docs/index.html")
