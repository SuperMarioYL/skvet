"""Scan supplied fixtures; never execute the fixture scripts."""
import json
from pathlib import Path
import subprocess
root = Path(__file__).resolve().parents[1]
for name in ("benign-skill", "malicious-skill"):
    result = subprocess.run(["./bin/skvet", "scan", "testdata/fixtures/" + name, "--json"], cwd=root, text=True, capture_output=True)
    report = json.loads(result.stdout)
    print(name + ": overall=" + report["overall"] + " exit=" + str(result.returncode))
    for verdict in report["verdicts"]:
        print("  score=" + str(verdict["score"]) + " rules=" + ",".join(sorted({f["rule_id"] for f in verdict["findings"]})))
    assert result.returncode == (2 if name == "malicious-skill" else 0)
print("Scope: static fixture analysis; no hooks, scripts or network calls executed.")
