"""Verify portable graph reports against installed npm 11.11.0, without networking.

Run: python tests/fixtures/replay_npm11_audit_reports.py /path/to/npm/package
The npm package must include its bundled dependencies. No install is performed.
These are graph/counter fixtures with an empty advisory state, not audit results.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def input_bytes(case: dict, fixtures: Path) -> dict[str, bytes]:
    if "manifest_fixture" in case:
        return {"package.json": (fixtures / case["manifest_fixture"]).read_bytes(),
                "package-lock.json": (fixtures / case["lock_fixture"]).read_bytes()}
    return {name: (json.dumps(case[key], indent=2) + "\n").encode()
            for name, key in (("package.json", "package"), ("package-lock.json", "lock"))}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("npm_root", type=Path)
    parser.add_argument("--refresh", action="store_true", help="Replace captured reports after review")
    args = parser.parse_args()
    node = shutil.which("node")
    if node is None:
        raise SystemExit("Node is required for the offline replay")
    fixtures = Path(__file__).resolve().parent
    snapshot = fixtures / "npm11-audit-reports.json"
    data = json.loads(snapshot.read_text(encoding="utf-8"))
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
    for name, case in data["cases"].items():
        with tempfile.TemporaryDirectory(prefix="npm11-report-") as temp:
            for filename, raw in input_bytes(case, fixtures).items():
                (Path(temp) / filename).write_bytes(raw)
            result = subprocess.run(
                [node, str(fixtures / "npm11-audit-report.cjs"), str(args.npm_root.resolve()), temp],
                capture_output=True, text=True, timeout=30, check=True, env=env,
            )
            observed = json.loads(result.stdout)
        if args.refresh:
            case["captured"] = observed
        else:
            assert observed == case["captured"], f"npm report drift for {name}"
        print(json.dumps({"case": name, "counters": observed["report"]["metadata"]["dependencies"]}))
    if args.refresh:
        snapshot.write_bytes((json.dumps(data, indent=2) + "\n").encode())


if __name__ == "__main__":
    main()
