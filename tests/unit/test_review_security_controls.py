import asyncio
from types import SimpleNamespace

import pytest

from omargate.analyze.codex.codex_runner import CodexRunner
from omargate.config import OmarGateConfig
from omargate.idempotency import compute_idempotency_key, review_config_digest
from omargate.preflight.dedupe import check_dedupe


@pytest.mark.parametrize("status", ["queued", "in_progress", "completed"])
@pytest.mark.parametrize("conclusion", [None, "success", "failure"])
def test_untrusted_check_markers_and_external_ids_never_skip_review(status, conclusion):
    forged = {"name": "Omar Gate", "external_id": "copied-key", "status": status,
              "conclusion": conclusion, "app": {"id": 123}, "output": {"summary": "copied-key"}}
    client = SimpleNamespace(find_check_run_by_external_id=lambda *_: forged,
                             list_check_runs=lambda *_: [forged])
    assert asyncio.run(check_dedupe(client, "same-head", "copied-key")) == (False, None)


@pytest.mark.parametrize("field,value", [("model", "gpt-6-sol"), ("model_fallback", "gpt-6-luna"),
    ("severity_gate", "P2"), ("llm_failure_policy", "deterministic_only"), ("review_routing", "intent-cascade-v1"),
    ("use_codex", False)])
def test_effective_settings_bind_idempotency(field, value):
    config = OmarGateConfig()
    changed = config.model_copy(update={field: value})
    before, after = review_config_digest(config), review_config_digest(changed)
    assert before != after
    common = dict(repo="test/repo", pr_number=1, head_sha="same", scan_mode="deep",
                  policy_pack="test", policy_pack_version="1", action_major_version="test")
    assert compute_idempotency_key(**common, config_digest=before) != compute_idempotency_key(**common, config_digest=after)


def test_pr_local_codex_is_rejected_even_when_present_on_path(tmp_path, monkeypatch):
    local = tmp_path / "node_modules/.bin/codex"
    local.parent.mkdir(parents=True)
    local.write_text("untrusted program")
    monkeypatch.setattr("omargate.analyze.codex.codex_runner.shutil.which", lambda _: str(local))
    assert CodexRunner("test-only")._resolve_codex_bin(tmp_path) is None
    monkeypatch.setattr("omargate.analyze.codex.codex_runner.shutil.which", lambda _: None)
    assert CodexRunner("test-only")._resolve_codex_bin(tmp_path) is None
