import copy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from test_review_cascade import configured as configured

from omargate.analyze.llm.context_builder import ContextBuilder
from omargate.analyze.review_cascade import LOW

pytestmark = pytest.mark.anyio


async def test_cascade_pr_context_covers_changed_source_without_unrelated_repository_truncation(request, monkeypatch):
    orchestrator = request.getfixturevalue("configured")
    orchestrator.context_builder = ContextBuilder(max_tokens=2000)
    (orchestrator.repo_root / "unrelated.py").write_text("unrelated_source = True\n" * 1000)
    response = AsyncMock(return_value=SimpleNamespace(success=True, content='{"no_findings":true}', usage=None))
    monkeypatch.setattr("omargate.analyze.orchestrator.LLMClient.analyze", response)
    ingest = {"files": [{"path": "x.py", "category": "source"}, {"path": "unrelated.py", "category": "source"}],
              "hotspots": {"auth": ["unrelated.py"]}}
    original = copy.deepcopy(ingest)
    result = await orchestrator._run_llm_analysis(ingest=ingest, deterministic_findings=[],
        quick_learn=None, spec_context=None, scan_mode="pr-diff", diff_content="+value = 1\n",
        changed_files=["x.py"], review_route=LOW)
    assert result.success and result.attempted
    source = response.call_args.kwargs["user_content"]
    assert "value = 1" in source and "unrelated_source" not in source
    assert ingest == original  # The global native inventory was never narrowed.


async def test_changed_file_still_cannot_be_clipped(request, monkeypatch):
    orchestrator = request.getfixturevalue("configured")
    (orchestrator.repo_root / "x.py").write_text("required = True\n" * 1000)
    response = AsyncMock(side_effect=AssertionError("no request on clipped source"))
    monkeypatch.setattr("omargate.analyze.orchestrator.LLMClient.analyze", response)
    result = await orchestrator._run_llm_analysis(ingest={"files": [{"path": "x.py", "category": "source"}]},
        deterministic_findings=[], quick_learn=None, spec_context=None, scan_mode="pr-diff",
        diff_content="+required = True\n", changed_files=["x.py"], review_route=LOW)
    assert not result.success and not result.attempted and result.failure_class == "cascade_context_incomplete"
    response.assert_not_awaited()
