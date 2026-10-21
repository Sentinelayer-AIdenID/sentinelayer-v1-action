"""Exercise workflow masking with synthetic secrets through the actual shell."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


def test_private_inputs_are_masked_before_any_workflow_commands():
    shell = shutil.which("sh")
    if not shell and os.name == "nt":
        candidate = Path("C:/Program Files/Git/usr/bin/sh.exe")
        shell = str(candidate) if candidate.is_file() else None
    if not shell:
        pytest.skip("POSIX shell is unavailable")
    root = Path(__file__).resolve().parents[2]
    prefix = (root / "entrypoint.sh").read_text(encoding="utf-8").split("required_envs=", 1)[0]
    prefix = "PATH=/usr/bin:$PATH\n" + prefix
    probe_env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "TEMP", "TMP") if key in os.environ}
    probe_env.update(
        INPUT_TYPESAFE_API_KEY="synthetic-percent%value",
        INPUT_INTENT_MODEL_PIN="fake-private-9.8.7",
        INPUT_INTENT_POLICY='{"synthetic":"first%line\rvalue"}\n{"second":true}',
    )
    result = subprocess.run([shell], input=prefix, env=probe_env, text=True, capture_output=True, check=True)
    assert result.stdout.splitlines() == [
        "::add-mask::synthetic-percent%25value",
        "::add-mask::fake-private-9.8.7",
        '::add-mask::{"synthetic":"first%25line%0Dvalue"}%0A{"second":true}',
    ]
    assert result.stderr == ""


def test_composite_masks_private_inputs_without_echoing_multiline_commands():
    root = Path(__file__).resolve().parents[2]
    env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "TEMP", "TMP") if key in os.environ}
    env.update(INPUT_TYPESAFE_API_KEY="fake-key%value", INPUT_INTENT_MODEL_PIN="fake-private-9.8.7",
               INPUT_INTENT_POLICY="fake%policy\r\n::notice::should-not-execute")
    result = subprocess.run([sys.executable, "-P", str(root / "src/omargate/mask_inputs.py")],
                            env=env, text=True, capture_output=True, check=True)
    assert result.stdout.splitlines() == [
        "::add-mask::fake-key%25value",
        "::add-mask::fake-private-9.8.7",
        "::add-mask::fake%25policy%0D%0A::notice::should-not-execute",
    ]
    source = (root / "action.yml").read_text()
    assert source.index("python -P -m omargate.mask_inputs") < source.index("python -P -m omargate.main")
