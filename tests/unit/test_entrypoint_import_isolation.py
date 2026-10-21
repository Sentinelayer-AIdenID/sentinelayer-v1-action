from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
ACTION_SOURCE = ROOT / "action.yml"
ENTRYPOINT_SOURCE = ROOT / "entrypoint.sh"


def test_action_and_container_entrypoints_enable_safe_path_mode() -> None:
    action = ACTION_SOURCE.read_text(encoding="utf-8")
    entrypoint = ENTRYPOINT_SOURCE.read_text(encoding="utf-8")

    assert 'export PYTHONPATH="${GITHUB_ACTION_PATH}/src"' in action
    assert 'export PYTHONPATH="${GITHUB_ACTION_PATH}/src:${PYTHONPATH:-}"' not in action
    assert "export PYTHONSAFEPATH=1" in action
    assert "python -P -m omargate.main" in action
    assert "python -m omargate.main" not in action

    assert 'export PYTHONPATH="/app/src"' in entrypoint
    assert 'export PYTHONPATH="/app/src:${PYTHONPATH:-}"' not in entrypoint
    assert "export PYTHONSAFEPATH=1" in entrypoint
    assert "exec python -P -m omargate.main" in entrypoint
    assert "exec python -m omargate.main" not in entrypoint


def test_dependency_install_cannot_import_workspace_shadowed_pip(tmp_path: Path) -> None:
    action = ACTION_SOURCE.read_text(encoding="utf-8")
    install_step = action.split("    - name: Install Omar Gate dependencies", 1)[1].split(
        "\n    - name:", 1
    )[0]
    working_directory = re.search(r"(?m)^\s+working-directory:\s*(.+)$", install_step)

    assert working_directory is not None
    assert working_directory.group(1).strip() == "${{ github.action_path }}"
    assert "python -P -m pip install" in install_step
    assert "python -m pip install" not in install_step

    workspace = tmp_path / "untrusted-workspace"
    decoy = workspace / "pip"
    decoy.mkdir(parents=True)
    marker = tmp_path / "workspace-pip-executed"
    (decoy / "__init__.py").write_text("", encoding="utf-8")
    (decoy / "__main__.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )

    probe_env = os.environ.copy()
    probe_env.pop("PYTHONPATH", None)
    probe_env.pop("PYTHONSAFEPATH", None)
    subprocess.run(
        [sys.executable, "-m", "pip", "--version"],
        cwd=workspace,
        env=probe_env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert marker.read_text(encoding="utf-8") == "executed"
    marker.unlink()

    subprocess.run(
        [sys.executable, "-P", "-m", "pip", "--version"],
        cwd=ROOT,
        env=probe_env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert not marker.exists()


def test_safe_path_mode_refuses_workspace_omargate_shadow(tmp_path: Path) -> None:
    workspace = tmp_path / "untrusted-workspace"
    decoy = workspace / "omargate"
    decoy.mkdir(parents=True)
    marker = tmp_path / "decoy-executed"
    (decoy / "__init__.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )

    probe = (
        "import json, omargate; "
        "print(json.dumps({'origin': omargate.__file__}))"
    )
    unsafe_env = os.environ.copy()
    unsafe_env.pop("PYTHONPATH", None)
    unsafe_env.pop("PYTHONSAFEPATH", None)
    unsafe = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=workspace,
        env=unsafe_env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(unsafe.stdout)["origin"].startswith(str(decoy))
    assert marker.read_text(encoding="utf-8") == "executed"
    marker.unlink()

    safe_env = os.environ.copy()
    safe_env["PYTHONPATH"] = str(ROOT / "src")
    safe_env["PYTHONSAFEPATH"] = "1"
    safe = subprocess.run(
        [sys.executable, "-P", "-c", probe],
        cwd=workspace,
        env=safe_env,
        check=True,
        capture_output=True,
        text=True,
    )
    origin = Path(json.loads(safe.stdout)["origin"]).resolve()
    assert origin == (ROOT / "src" / "omargate" / "__init__.py").resolve()
    assert not marker.exists()
