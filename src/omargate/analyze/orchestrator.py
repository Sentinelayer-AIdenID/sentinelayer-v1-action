from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import os
import re
from pathlib import Path
from types import MappingProxyType
from typing import List, Mapping, Optional

from ..artifacts import generate_review_brief
from ..config import OmarGateConfig
from ..ingest import (
    QuickLearnSummary,
    build_llm_synopsis_prompt,
    extract_quick_learn_summary,
    is_boilerplate_description,
    run_ingest,
)
from ..harness import HarnessRunner
from ..logging import OmarLogger
from ..package.fingerprint import add_fingerprints_to_findings
from ..fix_plan import ensure_fix_plan
from ..redaction import sanitize_public_error
from .codex import CodexPromptBuilder, CodexRunner
from .deterministic import (
    ConfigScanner,
    EngQualityScanner,
    PatternScanner,
    scan_for_secrets,
)
from .llm import (
    ContextBuilder,
    LLMClient,
    LLMResponse,
    LLMUsage,
    PromptLoader,
    ResponseParser,
    handle_llm_failure,
)
from .llm.providers import detect_provider_from_model
from .llm.response_parser import ParsedFinding
from .typesafe_client import TypeSafeClient, TypeSafeError
from .typesafe_review import (
    TypedReview,
    TypeSafeReviewIncomplete,
    build_inventory,
    load_policy,
    review_inventory,
    verify_sources,
)
from .typesafe_state import build_typed_context
from .typesafe_writer import explain_review, WRITER_MODEL


_LOG_SECRET_SCRUB_RES = (
    (re.compile(r"sk-[A-Za-z0-9_-]{16,}"), "[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"), "[REDACTED]"),
    (re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{16,}"), "[REDACTED]"),
    (re.compile(r"sk-(?:proj-)?[A-Za-z0-9_*.-]{8,}"), "[REDACTED]"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "[REDACTED]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{8,}"), "Bearer [REDACTED]"),
    (
        re.compile(
            r"(?i)((?:api[_-]?key|secret|token|password|authorization)\s*[=:]\s*)\S+"
        ),
        r"\1[REDACTED]",
    ),
)

# Only policy-declared categories and narrow, reviewed aliases can corroborate a
# blocking typed verdict. Generic labels such as ``web``/``backend`` remain
# incompatible and therefore downgrade P0/P1 findings to P2.
_CORROBORATION_CATEGORY_ALIASES: Mapping[str, str] = MappingProxyType({
    "auth": "auth",
    "auth_bypass": "auth",
    "csrf": "auth",
    "injection": "injection",
    "sql_injection": "injection",
    "sql-injection": "injection",
    "xss": "injection",
    "rce": "injection",
    "path_traversal": "injection",
    "path-traversal": "injection",
    "deserialization": "injection",
    "log_injection": "injection",
    "log-injection": "injection",
    "xxe": "injection",
    "ssti": "injection",
    "prompt_injection": "injection",
    "prompt-injection": "injection",
    "crypto": "crypto",
    "secrets": "secrets",
    "privacy": "privacy",
    "ssrf": "ssrf",
    "misconfig": "misconfig",
    "exposure": "exposure",
    "supply-chain": "supply-chain",
    "ci-cd": "ci-cd",
    "ci_cd": "ci-cd",
    "availability": "availability",
    "race-condition": "race-condition",
    "infrastructure": "infrastructure",
    "other-security": "other-security",
})

# No current deterministic/harness producer emits these reviewed categories.
# Their typed P0/P1 verdicts must trigger generator fallback and remain P2 until
# a narrow producer contract is implemented and tested.
_TYPED_CATEGORIES_REQUIRING_GENERATOR = frozenset({
    "availability",
    "race-condition",
    "other-security",
})


def _canonical_corroboration_category(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return _CORROBORATION_CATEGORY_ALIASES.get(value.strip().lower())


def _validated_typed_candidate_binding(
    finding: object,
) -> tuple[str, str, str] | None:
    """Return the immutable TypeSafe source binding carried by a finding."""
    if not isinstance(finding, dict):
        return None
    binding = finding.get("typed_candidate")
    if not isinstance(binding, dict):
        return None
    candidate_id = binding.get("candidate_id")
    source_sha256 = binding.get("source_sha256")
    evidence_sha256 = binding.get("evidence_sha256")
    if (
        not isinstance(candidate_id, str)
        or re.fullmatch(r"span-[0-9a-f]{64}", candidate_id) is None
        or not isinstance(source_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", source_sha256) is None
        or not isinstance(evidence_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", evidence_sha256) is None
    ):
        return None
    return candidate_id, source_sha256, evidence_sha256


def _coerce_finding_int(value: object, *, default: int | None = None) -> int | None:
    """Normalize a JSON-shaped finding value before integer operations."""
    if value is None:
        return default
    if not isinstance(value, (bool, int, float, str, bytes)):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _scrub_log_value(value):
    """Value-scrub known secret shapes before logging.

    OmarLogger._sanitize redacts by field NAME only; these diagnostic values
    (codex stderr/output) can carry the provider key / Bearer token / secret-
    bearing scanned source, so scrub the VALUE before it reaches the public run log.
    """
    if not value:
        return value
    scrubbed = str(value)
    for pattern, repl in _LOG_SECRET_SCRUB_RES:
        scrubbed = pattern.sub(repl, scrubbed)
    return scrubbed


def _writer_failure_class(error: Exception) -> str:
    """Return a bounded class without retaining provider or source-bearing text."""
    if isinstance(error, TimeoutError):
        return "typesafe_writer_timeout"
    if isinstance(error, TypeSafeReviewIncomplete):
        reason = str(error)
        if reason in {"typesafe_writer_failed", "typesafe_writer_invalid"}:
            return reason
    return "typesafe_writer_error"


def _preserve_review_after_writer_failure(
    review: TypedReview,
    *,
    failure_class: str,
) -> TypedReview:
    """Retain the completed typed decision and add only safe writer metadata."""
    findings = []
    for original in review.findings:
        finding = dict(original)
        finding.setdefault("typed_reason", finding.get("message", ""))
        finding.setdefault("typed_recommendation", finding.get("recommendation", ""))
        findings.append(finding)
    writer = {
        "provider": "openai",
        "requested_model": WRITER_MODEL,
        "success": False,
        "failure_class": failure_class,
    }
    assessment = {**review.assessment, "writer": writer}
    usage = {**review.usage, "typesafe_assessment": assessment}
    return TypedReview(findings, usage, assessment)


@dataclass
class AnalysisResult:
    """Complete analysis result."""

    findings: List[dict]
    quick_learn: Optional[QuickLearnSummary]
    ingest: dict
    counts: dict
    ingest_stats: dict
    deterministic_count: int
    llm_count: int
    llm_success: bool
    llm_usage: Optional[dict]
    warnings: List[str]
    review_brief_path: Optional[Path]
    scan_mode: str
    total_files_scanned: int
    hotspots_found: List[str]
    llm_attempted: bool = False
    llm_output_valid: bool = False
    llm_no_findings_reported: bool = False
    llm_reported_finding_count: int = 0
    llm_parse_error_count: int = 0
    llm_failure_class: Optional[str] = None


@dataclass
class LLMAnalysisResult:
    findings: List[dict]
    success: bool
    usage: Optional[dict]
    warning: Optional[str]
    attempted: bool = False
    output_valid: bool = False
    no_findings_reported: bool = False
    reported_finding_count: int = 0
    parse_error_count: int = 0
    failure_class: Optional[str] = None


class AnalysisOrchestrator:
    """Orchestrates the complete analysis pipeline."""

    def __init__(
        self,
        config: OmarGateConfig,
        logger: OmarLogger,
        repo_root: Path,
        allow_llm: bool = True,
    ) -> None:
        self.config = config
        self.logger = logger
        self.repo_root = repo_root
        self.allow_llm = allow_llm
        self._quick_learn: Optional[QuickLearnSummary] = None

        patterns_dir = Path(__file__).parent / "deterministic" / "patterns"
        self.pattern_scanner = PatternScanner(patterns_dir=patterns_dir)
        self.config_scanner = ConfigScanner(patterns_dir=patterns_dir)

        prompts_dir = Path(__file__).resolve().parents[3] / "prompts"
        self.prompt_loader = PromptLoader(prompts_dir=prompts_dir)

        self.context_builder = ContextBuilder(max_tokens=config.max_input_tokens)
        self.response_parser = ResponseParser()

    async def run(
        self,
        scan_mode: str = "pr-diff",
        diff_content: Optional[str] = None,
        changed_files: Optional[List[str]] = None,
        spec_context: Optional[dict] = None,
        run_dir: Optional[Path] = None,
        run_id: Optional[str] = None,
        version: Optional[str] = None,
        dashboard_url: Optional[str] = None,
    ) -> AnalysisResult:
        """
        Run complete analysis pipeline.

        Steps:
        1. Ingest codebase
        2. Run harness suites (optional)
        3. Run deterministic scans
        4. Build LLM context
        5. Run LLM analysis (with fallback)
        6. Merge and dedupe findings
        7. Return results
        """
        warnings: List[str] = []

        # Step 0: Quick Learn
        quick_learn: QuickLearnSummary
        with self.logger.stage("quick_learn"):
            quick_learn = await asyncio.to_thread(
                extract_quick_learn_summary, self.repo_root
            )
            self.logger.info(
                "Quick learn complete",
                source_doc=quick_learn.source_doc,
                tech_stack=quick_learn.tech_stack,
                architecture=quick_learn.architecture,
            )
        self._quick_learn = quick_learn

        # Step 1: Ingest
        with self.logger.stage("ingest"):
            ingest = run_ingest(
                self.repo_root,
                max_files=1000,
                max_file_size_bytes=1_000_000,
                logger=self.logger,
            )
            stats = ingest.get("stats", {})
            self.logger.info(
                "Ingest complete",
                total_files=stats.get("total_files"),
                in_scope=stats.get("in_scope_files"),
            )

        # Step 1.5: LLM synopsis synthesis — triggered when the README description is
        # scaffold boilerplate (e.g. Vite/CRA default text) and contributes nothing useful.
        # Makes a tiny, cheap LLM call to form a real one-sentence project opinion.
        _has_llm_key = bool(
            self.config.use_managed_llm_proxy()
            or self.config.openai_api_key.get_secret_value()
            or self.config.anthropic_api_key.get_secret_value()
            or self.config.google_api_key.get_secret_value()
        )
        if (
            quick_learn
            and self.allow_llm
            and self.config.llm_provider != "typesafe"
            and _has_llm_key
            and is_boilerplate_description(quick_learn.description)
        ):
            with self.logger.stage("synopsis_synthesis"):
                try:
                    ingest_files = (
                        ingest.get("files", []) if isinstance(ingest, dict) else []
                    )
                    largest_files = sorted(
                        [
                            f
                            for f in ingest_files
                            if isinstance(f, dict) and f.get("path")
                        ],
                        key=lambda f: -int(f.get("lines") or 0),
                    )[:10]
                    largest_paths = [str(f["path"]) for f in largest_files]
                    synopsis_client = LLMClient(
                        api_key=self.config.openai_api_key.get_secret_value(),
                        primary_model=self.config.model,
                        fallback_model=self.config.model_fallback,
                        llm_provider=self._generator_provider(),
                        anthropic_api_key=self.config.anthropic_api_key.get_secret_value(),
                        google_api_key=self.config.google_api_key.get_secret_value(),
                        xai_api_key=self.config.xai_api_key.get_secret_value(),
                        managed_llm=self._should_use_managed_proxy_for_llm_analysis(),
                        managed_capacity_fallback=self._should_allow_managed_capacity_fallback(),
                        sentinelayer_token=self.config.sentinelayer_token.get_secret_value(),
                        managed_api_url=os.environ.get(
                            "SENTINELAYER_API_URL", "https://api.sentinelayer.com"
                        ),
                    )
                    synopsis_response = await synopsis_client.analyze(
                        system_prompt="You are a technical writer. Reply with exactly one sentence.",
                        user_content=build_llm_synopsis_prompt(
                            quick_learn, largest_paths
                        ),
                        max_tokens=80,
                    )
                    if synopsis_response.success and synopsis_response.content.strip():
                        synthesized = (
                            synopsis_response.content.strip().strip('"').strip()
                        )
                        quick_learn.description = synthesized[:120]
                        self._quick_learn = quick_learn
                        self.logger.info(
                            "Synopsis synthesized", synopsis=quick_learn.description
                        )
                except Exception as exc:
                    self.logger.warning("Synopsis synthesis skipped", error=str(exc))

        # Step 2: Harness (portable suites)
        harness_findings: List[dict] = []
        if self.config.run_harness:
            with self.logger.stage("harness"):
                try:
                    runner = HarnessRunner(
                        project_root=str(self.repo_root),
                        tech_stack=quick_learn.tech_stack if quick_learn else [],
                        pip_audit_ignore_ids=self.config.pip_audit_ignore_ids,
                    )
                    harness_results = await runner.run()
                    harness_findings = [
                        self._finding_to_dict(f) for f in harness_results
                    ]
                    self.logger.info(
                        "Harness complete",
                        findings_count=len(harness_findings),
                    )
                except Exception as exc:
                    self.logger.warning("Harness failed", error=str(exc))
                    warnings.append("Harness failed")
        else:
            warnings.append("Harness skipped (run_harness=false)")

        # Step 3: Deterministic scans
        with self.logger.stage("deterministic_scan"):
            det_findings = self._run_deterministic_scans(ingest)
            self.logger.info(
                "Deterministic scan complete",
                findings_count=len(det_findings),
            )

        # Step 4-5: Deep scan via Codex CLI, then API/managed LLM fallback.
        llm_findings: List[dict] = []
        llm_success = False
        llm_usage: Optional[dict] = None
        llm_attempted = False
        llm_output_valid = False
        llm_no_findings_reported = False
        llm_reported_finding_count = 0
        llm_parse_error_count = 0
        llm_failure_class: Optional[str] = "not_attempted"
        generator_result_recorded = False

        def record_llm_result(result: LLMAnalysisResult) -> None:
            nonlocal llm_attempted
            nonlocal llm_failure_class
            nonlocal llm_findings
            nonlocal llm_no_findings_reported
            nonlocal llm_output_valid
            nonlocal llm_parse_error_count
            nonlocal llm_reported_finding_count
            nonlocal llm_success
            nonlocal llm_usage

            llm_attempted = llm_attempted or result.attempted
            llm_success = result.success
            llm_output_valid = result.output_valid
            llm_no_findings_reported = result.no_findings_reported
            llm_reported_finding_count = result.reported_finding_count
            llm_parse_error_count = result.parse_error_count
            llm_failure_class = result.failure_class
            llm_findings = result.findings
            llm_usage = result.usage

        async def run_llm_stage(stage_name: str, completion_event: str) -> None:
            nonlocal generator_result_recorded

            generator_result_recorded = True
            with self.logger.stage(stage_name):
                try:
                    result = await self._run_llm_analysis(
                        ingest=ingest,
                        deterministic_findings=det_findings,
                        quick_learn=quick_learn,
                        spec_context=spec_context,
                        scan_mode=scan_mode,
                        diff_content=diff_content,
                        changed_files=changed_files,
                    )
                    for finding in result.findings:
                        actual_model = (result.usage or {}).get("model") or self.config.model
                        finding.setdefault("model_source", actual_model)
                    self.logger.info(
                        completion_event,
                        model=self.config.model,
                        success=result.success,
                        findings_count=len(result.findings),
                    )
                    record_llm_result(result)
                    if result.warning:
                        warnings.append(result.warning)
                except Exception as exc:
                    self.logger.warning(
                        f"{completion_event} failed",
                        model=self.config.model,
                        error=str(exc),
                    )
                    warnings.append(
                        f"{self.config.model} LLM analysis failed: "
                        f"{sanitize_public_error(exc)}"
                    )
                    record_llm_result(
                        self._llm_failure_result(
                            deterministic_findings=det_findings,
                            attempted=True,
                            failure_class="execution_error",
                            public_error="LLM analysis raised an execution error",
                        )
                    )

        typed_result: Optional[LLMAnalysisResult] = None
        if self.allow_llm and self.config.llm_provider == "typesafe":
            with self.logger.stage("typesafe_review"):
                typed_result = await self._run_typesafe_analysis(
                    ingest=ingest,
                    changed_files=changed_files,
                    scan_mode=scan_mode,
                    deterministic_findings=det_findings,
                    run_dir=run_dir,
                    diff_content=diff_content,
                )
                record_llm_result(typed_result)
                if typed_result.warning:
                    warnings.append(typed_result.warning)

        run_generator = self.config.llm_provider != "typesafe" or (
            not llm_success and self.config.typesafe_fallback
        )
        if run_generator and self.allow_llm and self.config.use_codex:
            generator_result_recorded = True
            with self.logger.stage("deep_scan"):
                codex_model = self.config.codex_model
                try:
                    result = await self._run_codex_audit(
                        ingest=ingest,
                        deterministic_findings=det_findings,
                        quick_learn=quick_learn,
                        scan_mode=scan_mode,
                        diff_content=diff_content,
                        codex_model_override=codex_model,
                    )
                    for f in result.findings:
                        f["model_source"] = codex_model
                    self.logger.info(
                        "Codex scan complete",
                        model=codex_model,
                        success=result.success,
                        findings_count=len(result.findings),
                    )
                    record_llm_result(result)
                    if result.warning:
                        warnings.append(result.warning)
                except Exception as exc:
                    self.logger.warning(
                        "Codex scan failed",
                        model=codex_model,
                        error=str(exc),
                    )
                    warnings.append(
                        f"{codex_model} Codex scan failed: {sanitize_public_error(exc)}"
                    )
                    record_llm_result(
                        self._llm_failure_result(
                            deterministic_findings=det_findings,
                            attempted=True,
                            failure_class="codex_execution_error",
                            public_error="Codex analysis raised an execution error",
                        )
                    )
            if (
                not llm_success
                and not self.config.codex_only
                and self._should_run_llm()
            ):
                await run_llm_stage("llm_fallback", "LLM fallback complete")
            elif not llm_success and not self.config.codex_only:
                warnings.append("LLM analysis skipped (no API key or limited mode)")
        elif run_generator and self._should_run_llm():
            await run_llm_stage("llm_analysis", "LLM analysis complete")
        elif not run_generator:
            pass
        elif not self.allow_llm:
            warnings.append("LLM analysis skipped (no API key or limited mode)")
        else:
            warnings.append("LLM analysis skipped (no API key or limited mode)")

        if (
            typed_result is not None
            and typed_result.findings
            and generator_result_recorded
        ):
            llm_findings = self._compose_llm_findings(
                typed_result.findings,
                llm_findings,
            )
            llm_no_findings_reported = False
            llm_reported_finding_count = len(llm_findings)

        if not llm_success and not llm_findings and not llm_output_valid:
            record_llm_result(
                self._llm_failure_result(
                    deterministic_findings=det_findings,
                    attempted=llm_attempted,
                    failure_class=llm_failure_class or "not_attempted",
                    public_error="No valid LLM review result was available",
                    usage=llm_usage,
                    parse_error_count=llm_parse_error_count,
                )
            )

        if typed_result is not None:
            llm_usage = dict(llm_usage or {})
            llm_usage["typesafe_attempt"] = {
                "requested_model": self.config.typesafe_model,
                "attempted": typed_result.attempted,
                "success": typed_result.success,
                "failure_class": typed_result.failure_class,
            }
            if generator_result_recorded:
                prior_usage = typed_result.usage or {}
                if prior_usage.get("typesafe_assessment") is not None:
                    llm_usage["typesafe_assessment"] = prior_usage["typesafe_assessment"]
                if prior_usage.get("typesafe_usage") is not None:
                    llm_usage["typesafe_usage"] = prior_usage["typesafe_usage"]
                actual_provider = llm_usage.get("provider") or "unknown"
                actual_model = llm_usage.get("model") or "unknown"
                llm_usage["fallback_chain"] = (
                    f"typesafe/{self.config.typesafe_model} -> "
                    f"{actual_provider}/{actual_model}"
                )

        # Step 6: Merge findings
        base_findings = harness_findings + det_findings
        llm_findings = self._apply_llm_guardrails(
            llm_findings=llm_findings,
            non_llm_findings=base_findings,
            ingest=ingest,
        )
        all_findings = self._merge_findings(base_findings, llm_findings)
        add_fingerprints_to_findings(
            all_findings,
            policy_version=self.config.policy_pack_version,
            tenant_salt="",
        )
        counts = self._count_by_severity(all_findings)

        review_brief_path: Optional[Path] = None
        if run_dir and run_id:
            try:
                review_brief_path = generate_review_brief(
                    run_dir=run_dir,
                    run_id=run_id,
                    findings=all_findings,
                    ingest=ingest,
                    scan_mode=scan_mode,
                    version=version or "unknown",
                    dashboard_url=dashboard_url,
                )
            except Exception as exc:
                self.logger.warning("Review brief generation failed", error=str(exc))
                warnings.append("Review brief generation failed")

        hotspots_with_findings = self._identify_hotspots_with_findings(
            all_findings, ingest.get("hotspots", {})
        )

        stats = ingest.get("stats", {})

        return AnalysisResult(
            findings=all_findings,
            quick_learn=quick_learn,
            ingest=ingest,
            counts=counts,
            ingest_stats=stats,
            deterministic_count=len(det_findings),
            llm_count=len(llm_findings),
            llm_success=llm_success,
            llm_usage=llm_usage,
            warnings=warnings,
            review_brief_path=review_brief_path,
            scan_mode=scan_mode,
            total_files_scanned=int(stats.get("in_scope_files", 0) or 0),
            hotspots_found=hotspots_with_findings,
            llm_attempted=llm_attempted,
            llm_output_valid=llm_output_valid,
            llm_no_findings_reported=llm_no_findings_reported,
            llm_reported_finding_count=llm_reported_finding_count,
            llm_parse_error_count=llm_parse_error_count,
            llm_failure_class=llm_failure_class,
        )

    def _should_run_llm(self) -> bool:
        """Check if LLM analysis should run."""
        if not self.allow_llm:
            return False
        primary_provider = detect_provider_from_model(
            self.config.model, default_provider=self._generator_provider()
        )
        if (
            primary_provider == "openai"
            and self._should_use_managed_proxy_for_llm_analysis()
        ):
            return True
        api_key = self._get_provider_api_key(primary_provider)
        return bool(api_key)

    def _should_use_managed_proxy_for_llm_analysis(self) -> bool:
        """Use managed proxy only when the OpenAI fallback path has no BYO key."""
        primary_provider = detect_provider_from_model(
            self.config.model, default_provider=self._generator_provider()
        )
        if primary_provider != "openai":
            return False
        if self.config.openai_api_key.get_secret_value():
            return False
        return self.config.use_managed_llm_proxy()

    def _should_allow_managed_capacity_fallback(self) -> bool:
        """Allow managed proxy only as a final BYO quota/rate-limit fallback."""
        return bool(
            self.config.llm_provider != "typesafe"
            and
            self.config.sentinelayer_managed_llm
            and self.config.sentinelayer_token.get_secret_value()
        )

    def _get_provider_api_key(self, provider: str) -> str:
        if provider == "openai":
            return self.config.openai_api_key.get_secret_value()
        if provider == "anthropic":
            return self.config.anthropic_api_key.get_secret_value()
        if provider == "google":
            return self.config.google_api_key.get_secret_value()
        if provider == "xai":
            return self.config.xai_api_key.get_secret_value()
        return ""

    def _generator_provider(self) -> str:
        # TypeSafe is a separate typed stage, never a free-text provider alias.
        return "openai" if self.config.llm_provider == "typesafe" else self.config.llm_provider

    async def _run_typesafe_analysis(
        self, *, ingest: dict, changed_files: Optional[List[str]], scan_mode: str,
        deterministic_findings: List[dict], run_dir: Optional[Path] = None,
        diff_content: Optional[str] = None,
    ) -> LLMAnalysisResult:
        attempted = False
        client = None
        typed_usage = None
        writer_warning = None
        metadata: dict = {
            "requested_provider": "typesafe", "requested_model": self.config.typesafe_model,
            "complete": False,
        }
        try:
            inventory = build_inventory(
                repo_root=self.repo_root, ingest=ingest, changed_files=changed_files,
                scan_mode=scan_mode, max_candidates=self.config.typesafe_max_candidates,
            )
            policy = load_policy()
            context = build_typed_context(
                repo_root=self.repo_root, inventory=inventory, ingest=ingest,
                diff_content=diff_content, deterministic_findings=deterministic_findings,
            )
            client = TypeSafeClient(
                self.config.typesafe_api_key.get_secret_value(),
                timeout_seconds=self.config.typesafe_timeout,
            )
            review = await review_inventory(
                repo_root=self.repo_root, inventory=inventory, policy=policy,
                client=client, model=self.config.typesafe_model, context=context,
            )
            metadata = review.assessment
            typed_usage = review.usage
            if review.findings:
                try:
                    writer = LLMClient(
                        api_key=self.config.openai_api_key.get_secret_value(),
                        primary_model=WRITER_MODEL,
                        fallback_model=WRITER_MODEL,
                        llm_provider="openai",
                        managed_llm=False,
                        managed_capacity_fallback=False,
                    )
                    review = await explain_review(review, client=writer)
                except Exception as error:
                    review = _preserve_review_after_writer_failure(
                        review,
                        failure_class=_writer_failure_class(error),
                    )
                    writer_warning = (
                        "TypeSafe writer did not complete; policy-owned typed "
                        "verdicts were preserved."
                    )
                metadata = review.assessment
                typed_usage = review.usage
            verify_sources(self.repo_root, inventory)
            attempted = bool(client.attempted)
            policy_complete = review.assessment.get("complete") is True
            generator_required = set()
            for finding in review.findings:
                category = _canonical_corroboration_category(
                    finding.get("category")
                )
                if (
                    finding.get("severity") in {"P0", "P1"}
                    and category is not None
                    and category in _TYPED_CATEGORIES_REQUIRING_GENERATOR
                ):
                    generator_required.add(category)
            generator_required_categories = sorted(generator_required)
            if generator_required_categories:
                review.assessment["generator_required_categories"] = (
                    generator_required_categories
                )
            warning: Optional[str]
            if policy_complete and review.findings and generator_required_categories:
                success = False
                failure_class = "typesafe_category_requires_generator"
                warning = (
                    "TypeSafe blocking category lacks a reviewed deterministic "
                    "corroboration producer; generator review is required and the "
                    "finding remains non-blocking without corroboration."
                )
                if writer_warning:
                    warning += " The TypeSafe writer also did not complete."
            elif policy_complete and review.findings:
                success = True
                failure_class = None
                warning = writer_warning
            elif policy_complete:
                success = False
                failure_class = "typesafe_clean_requires_generator"
                warning = (
                    "TypeSafe clean review requires generator confirmation until "
                    "empirical recall evidence is available."
                )
            else:
                success = False
                failure_class = review.assessment.get("decision_reason")
                if not isinstance(failure_class, str) or not re.fullmatch(
                    r"[a-z][a-z0-9_]{0,95}", failure_class
                ):
                    failure_class = "typed_review_incomplete"
                warning = (
                    "TypeSafe review was incomplete; confirmed policy findings "
                    "were preserved and generator review is required."
                )
                if writer_warning:
                    warning += " The TypeSafe writer also did not complete."
            result = LLMAnalysisResult(
                findings=review.findings, success=success, usage=review.usage,
                warning=warning, attempted=attempted, output_valid=True,
                no_findings_reported=policy_complete and not review.findings,
                reported_finding_count=len(review.findings),
                failure_class=failure_class,
            )
        except (TypeSafeReviewIncomplete, TypeSafeError) as exc:
            attempted = bool(client is not None and client.attempted)
            reason = str(exc) if isinstance(exc, TypeSafeReviewIncomplete) else "typesafe_transport_failure"
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", reason):
                reason = "typed_review_incomplete"
            metadata["failure_class"] = reason
            result = self._llm_failure_result(
                deterministic_findings=deterministic_findings, attempted=attempted,
                failure_class=reason, public_error="Typed review did not complete",
                usage=typed_usage,
            )
        except Exception:
            attempted = bool(client is not None and client.attempted)
            # Policy/transport bugs cannot publish source-bearing exception bodies
            # or turn an incomplete review into successful no-findings.
            metadata["failure_class"] = "typesafe_execution_error"
            result = self._llm_failure_result(
                deterministic_findings=deterministic_findings, attempted=attempted,
                failure_class="typesafe_execution_error",
                public_error="Typed review raised an execution error",
                usage=typed_usage,
            )
        metadata["http_attempted"] = attempted
        policy_decision_complete = metadata.get("complete") is True
        metadata["policy_decision_complete"] = policy_decision_complete
        metadata["typed_assessment_complete"] = policy_decision_complete
        metadata["complete"] = result.success
        metadata["review_complete"] = result.success
        if result.failure_class:
            metadata["failure_class"] = result.failure_class
        if result.usage is None:
            result.usage = {
                "provider": "typesafe", "model": None,
                "requested_model": self.config.typesafe_model,
                "tokens_in": None, "tokens_out": None, "cost_usd": None,
                "typesafe_assessment": metadata,
            }
        if run_dir is not None:
            try:
                destination = run_dir / "TYPESAFE_REVIEW.json"
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(
                    json.dumps(metadata, sort_keys=True, allow_nan=False) + "\n",
                    encoding="utf-8",
                )
            except (OSError, TypeError, ValueError):
                metadata["failure_class"] = "typesafe_evidence_write_failed"
                metadata["complete"] = False
                metadata["review_complete"] = False
                result = self._llm_failure_result(
                    deterministic_findings=deterministic_findings, attempted=attempted,
                    failure_class="typesafe_evidence_write_failed",
                    public_error="Typed review evidence could not be retained",
                    usage=result.usage,
                )
        return result

    @staticmethod
    def _llm_usage_to_dict(usage) -> Optional[dict]:
        if not usage:
            return None
        payload = {
            "model": usage.model,
            "provider": getattr(usage, "provider", None),
            "tokens_in": usage.tokens_in,
            "tokens_out": usage.tokens_out,
            "cost_usd": usage.cost_usd,
            "latency_ms": usage.latency_ms,
        }
        route = getattr(usage, "route", None)
        if route and route != "byo":
            payload["route"] = route
        fallback_chain = getattr(usage, "fallback_chain", None)
        if fallback_chain:
            payload["fallback_chain"] = fallback_chain
        return payload

    def _run_deterministic_scans(self, ingest: dict) -> List[dict]:
        """Run all deterministic scanners."""
        findings: List[dict] = []

        pattern_findings = self.pattern_scanner.scan_files(
            ingest.get("files", []),
            self.repo_root,
        )
        findings.extend(self._finding_to_dict(f) for f in pattern_findings)

        for file_info in ingest.get("files", []):
            if file_info.get("category") != "source":
                continue
            rel_path = file_info.get("path")
            if not rel_path:
                continue
            try:
                content = (self.repo_root / rel_path).read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
            except OSError:
                continue
            secret_findings = scan_for_secrets(content, rel_path)
            findings.extend(self._finding_to_dict(f) for f in secret_findings)

        config_findings = self.config_scanner.scan_files(
            ingest.get("files", []),
            self.repo_root,
        )
        findings.extend(self._finding_to_dict(f) for f in config_findings)

        # Stack-aware engineering quality checks (inline rules).
        tech_stack = self._quick_learn.tech_stack if self._quick_learn else []
        eng_files = self._load_files_for_quality_scans(ingest)
        eng_scanner = EngQualityScanner(tech_stack=tech_stack)
        eng_findings = eng_scanner.scan(eng_files)
        findings.extend(self._finding_to_dict(f) for f in eng_findings)

        return findings

    def _load_files_for_quality_scans(self, ingest: dict) -> dict[str, str]:
        """
        Load a bounded set of file contents for stack-aware quality scanning.

        Uses ingest's in-scope file list; avoids reading huge files.
        """
        files: dict[str, str] = {}
        for file_info in ingest.get("files", []) or []:
            rel_path = file_info.get("path")
            if not rel_path:
                continue
            size_bytes = file_info.get("size_bytes")
            if isinstance(size_bytes, int) and size_bytes > 1_000_000:
                continue
            try:
                content = (self.repo_root / rel_path).read_text(
                    encoding="utf-8", errors="ignore"
                )
            except OSError:
                continue
            files[rel_path] = content
        # Ensure key infra files are included if present.
        for rel_path in ("Dockerfile", ".env"):
            if rel_path in files:
                continue
            try:
                p = self.repo_root / rel_path
                if p.is_file():
                    files[rel_path] = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                pass
        return files

    async def _run_llm_analysis(
        self,
        ingest: dict,
        deterministic_findings: List[dict],
        quick_learn: Optional[QuickLearnSummary],
        spec_context: Optional[dict],
        scan_mode: str,
        diff_content: Optional[str],
        changed_files: Optional[List[str]],
    ) -> LLMAnalysisResult:
        """Run LLM analysis with fallback handling."""
        context = self.context_builder.build_context(
            ingest=ingest,
            deterministic_findings=deterministic_findings,
            repo_root=self.repo_root,
            quick_learn=quick_learn,
            spec_context=spec_context,
            scan_mode=scan_mode,
            diff_content=diff_content,
            changed_files=changed_files,
        )

        system_prompt = self.prompt_loader.get_prompt(scan_mode=scan_mode)

        client = LLMClient(
            api_key=self.config.openai_api_key.get_secret_value(),
            primary_model=self.config.model,
            fallback_model=self.config.model_fallback,
            llm_provider=self._generator_provider(),
            anthropic_api_key=self.config.anthropic_api_key.get_secret_value(),
            google_api_key=self.config.google_api_key.get_secret_value(),
            xai_api_key=self.config.xai_api_key.get_secret_value(),
            managed_llm=self._should_use_managed_proxy_for_llm_analysis(),
            managed_capacity_fallback=self._should_allow_managed_capacity_fallback(),
            sentinelayer_token=self.config.sentinelayer_token.get_secret_value(),
            managed_api_url=os.environ.get(
                "SENTINELAYER_API_URL", "https://api.sentinelayer.com"
            ),
        )

        response = await client.analyze(
            system_prompt=system_prompt,
            user_content=context.content,
            max_tokens=4096,
        )

        if not response.success:
            return self._llm_failure_result(
                deterministic_findings=deterministic_findings,
                attempted=True,
                failure_class="provider_failure",
                public_error=response.error or "LLM provider request failed",
                usage=self._llm_usage_to_dict(response.usage),
            )

        parse_result = self.response_parser.parse(response.content)
        if parse_result.parse_errors:
            self.logger.warning(
                "llm_parse_errors",
                count=len(parse_result.parse_errors),
            )

        reported_finding_count = len(parse_result.findings)
        no_findings_reported = parse_result.no_findings_reported
        parse_error_count = len(parse_result.parse_errors)
        output_valid = parse_error_count == 0 and (
            (reported_finding_count > 0 and not no_findings_reported)
            or (reported_finding_count == 0 and no_findings_reported)
        )
        if not output_valid:
            return self._llm_failure_result(
                deterministic_findings=deterministic_findings,
                attempted=True,
                failure_class="invalid_output",
                public_error="LLM output failed the structured response contract",
                usage=self._llm_usage_to_dict(response.usage),
                no_findings_reported=no_findings_reported,
                reported_finding_count=reported_finding_count,
                parse_error_count=parse_error_count,
            )

        return LLMAnalysisResult(
            findings=[self._parsed_finding_to_dict(f) for f in parse_result.findings],
            success=True,
            usage=self._llm_usage_to_dict(response.usage),
            warning=None,
            attempted=True,
            output_valid=True,
            no_findings_reported=no_findings_reported,
            reported_finding_count=reported_finding_count,
            parse_error_count=0,
            failure_class=None,
        )

    async def _run_codex_audit(
        self,
        *,
        ingest: dict,
        deterministic_findings: List[dict],
        quick_learn: Optional[QuickLearnSummary],
        scan_mode: str,
        diff_content: Optional[str],
        codex_model_override: Optional[str] = None,
    ) -> LLMAnalysisResult:
        """
        Run Codex CLI agentic audit and parse JSONL findings.

        Returns: LLMAnalysisResult (findings, success, usage, warning_message)
        """
        api_key = self.config.openai_api_key.get_secret_value()
        if not api_key:
            result = self._llm_failure_result(
                deterministic_findings=deterministic_findings,
                attempted=False,
                failure_class="missing_credentials",
                public_error="Codex analysis did not have provider credentials",
            )
            if self.config.use_managed_llm_proxy():
                result.warning = None
            return result

        tech_stack = quick_learn.tech_stack if quick_learn else []
        hotspots = self._flatten_hotspots(ingest.get("hotspots", {}) or {})

        builder = CodexPromptBuilder(max_tokens=self.config.max_input_tokens)
        built = builder.build_prompt(
            repo_root=self.repo_root,
            quick_learn=quick_learn,
            deterministic_findings=deterministic_findings,
            tech_stack=tech_stack,
            scan_mode=scan_mode,
            diff_content=diff_content,
            hotspot_files=hotspots,
            ingest=ingest,
        )

        active_model = codex_model_override or self.config.codex_model
        runner = CodexRunner(api_key=api_key, model=active_model)
        result = await runner.run_audit(
            prompt=built.prompt,
            working_dir=str(self.repo_root),
            sandbox="read-only",
            timeout=int(self.config.codex_timeout),
        )
        parse_error_count = len(result.parse_errors or [])
        reported_finding_count = len(result.findings)
        no_findings_reported = result.no_findings_reported
        output_valid = parse_error_count == 0 and (
            (reported_finding_count > 0 and not no_findings_reported)
            or (reported_finding_count == 0 and no_findings_reported)
        )
        if not result.success or not output_valid:
            warn = sanitize_public_error(result.error or "Codex audit failed")
            # `--json` supplies the terminal CLI error without logging the echoed prompt.
            self.logger.warning(
                "Codex primary failed (diagnostic)",
                model=active_model,
                error=_scrub_log_value(result.error),
                parse_errors=[
                    _scrub_log_value(p) for p in (result.parse_errors or [])[:5]
                ],
                duration_ms=result.duration_ms,
            )
            failure_class = (
                "invalid_output"
                if parse_error_count > 0 or (result.success and not output_valid)
                else "codex_failure"
            )
            failed = self._llm_failure_result(
                deterministic_findings=deterministic_findings,
                attempted=True,
                failure_class=failure_class,
                public_error=(
                    "Codex output failed the structured response contract"
                    if failure_class == "invalid_output"
                    else "Codex analysis failed"
                ),
                no_findings_reported=no_findings_reported,
                reported_finding_count=reported_finding_count,
                parse_error_count=parse_error_count,
            )
            failed.warning = (
                f"Codex audit failed ({warn}). Falling back to LLM analysis."
            )
            return failed

        # Codex CLI currently doesn't provide token/cost accounting. Keep cost unknown.
        return LLMAnalysisResult(
            findings=result.findings,
            success=True,
            usage={
                "engine": "codex",
                "provider": "openai",
                "model": active_model,
                "tokens_in": None,
                "tokens_out": None,
                "cost_usd": None,
                "latency_ms": int(result.duration_ms),
            },
            warning=None,
            attempted=True,
            output_valid=True,
            no_findings_reported=no_findings_reported,
            reported_finding_count=reported_finding_count,
            parse_error_count=0,
            failure_class=None,
        )

    def _llm_failure_result(
        self,
        *,
        deterministic_findings: List[dict],
        attempted: bool,
        failure_class: str,
        public_error: str,
        usage: Optional[dict] = None,
        no_findings_reported: bool = False,
        reported_finding_count: int = 0,
        parse_error_count: int = 0,
    ) -> LLMAnalysisResult:
        usage_payload = usage or {}
        failure_response = LLMResponse(
            content="",
            usage=LLMUsage(
                model=str(usage_payload.get("model") or self.config.model),
                tokens_in=int(usage_payload.get("tokens_in") or 0),
                tokens_out=int(usage_payload.get("tokens_out") or 0),
                cost_usd=float(usage_payload.get("cost_usd") or 0.0),
                latency_ms=int(usage_payload.get("latency_ms") or 0),
                provider=str(usage_payload.get("provider") or self.config.llm_provider),
            ),
            success=False,
            error=public_error,
        )
        policy_result = handle_llm_failure(
            llm_response=failure_response,
            deterministic_findings=deterministic_findings,
            policy=self.config.llm_failure_policy,
        )
        non_deterministic = [
            finding
            for finding in policy_result.findings
            if finding.source != "deterministic"
        ]
        warning = policy_result.warning_message
        if warning is None and self.config.llm_failure_policy != "block":
            warning = "LLM analysis did not produce a valid review result."
        return LLMAnalysisResult(
            findings=[
                self._parsed_finding_to_dict(finding) for finding in non_deterministic
            ],
            success=False,
            usage=usage,
            warning=warning,
            attempted=attempted,
            output_valid=False,
            no_findings_reported=bool(no_findings_reported),
            reported_finding_count=max(0, int(reported_finding_count)),
            parse_error_count=max(0, int(parse_error_count)),
            failure_class=failure_class,
        )

    def _flatten_hotspots(self, hotspots: dict) -> List[str]:
        files: List[str] = []
        seen = set()
        for group in hotspots.values():
            if not isinstance(group, list):
                continue
            for rel_path in group:
                if not rel_path or rel_path in seen:
                    continue
                seen.add(rel_path)
                files.append(rel_path)
        return files

    def _merge_findings(self, deterministic: List[dict], llm: List[dict]) -> List[dict]:
        """Merge findings, dedupe by file+line+category."""
        seen = set()
        merged: List[dict] = []

        for finding in deterministic:
            key = (
                finding.get("file_path"),
                finding.get("line_start"),
                finding.get("category"),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(finding)

        for finding in llm:
            key = (
                finding.get("file_path"),
                finding.get("line_start"),
                finding.get("category"),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(finding)

        severity_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

        def finding_sort_key(finding: dict) -> tuple[int, str]:
            raw_severity = finding.get("severity")
            severity = raw_severity if isinstance(raw_severity, str) else ""
            raw_path = finding.get("file_path")
            path = raw_path if isinstance(raw_path, str) else ""
            return severity_order.get(severity, 4), path

        merged.sort(
            key=finding_sort_key
        )

        return merged

    @staticmethod
    def _compose_llm_findings(
        typed_findings: List[dict], generator_findings: List[dict]
    ) -> List[dict]:
        """Keep typed verdicts and drop only exact source-bound fallback overlap."""

        def span_key(finding: dict) -> tuple[str, int, int, str] | None:
            path = finding.get("file_path")
            category = _canonical_corroboration_category(finding.get("category"))
            if not isinstance(path, str) or category is None:
                return None
            line_start = _coerce_finding_int(finding.get("line_start"))
            if line_start is None:
                return None
            line_end = _coerce_finding_int(
                finding.get("line_end") or line_start
            )
            if line_end is None:
                return None
            if line_start < 1 or line_end < line_start:
                return None
            return (path.replace("\\", "/"), line_start, line_end, category)

        composed = list(typed_findings)
        typed_bindings: dict[tuple[str, int, int, str], tuple[str, str, str]] = {}
        for finding in typed_findings:
            if not isinstance(finding, dict):
                continue
            key = span_key(finding)
            binding = _validated_typed_candidate_binding(finding)
            if binding is None or key is None:
                continue
            typed_bindings[key] = binding

        for finding in generator_findings:
            if isinstance(finding, dict) and span_key(finding) in typed_bindings:
                continue
            composed.append(finding)
        return composed

    def _apply_llm_guardrails(
        self,
        *,
        llm_findings: List[dict],
        non_llm_findings: List[dict],
        ingest: dict,
    ) -> List[dict]:
        """
        Normalize and guardrail LLM/Codex findings before merge.

        Rules:
        - Ignore findings pointing to unknown files.
        - Clamp line numbers to file bounds when ingest line counts are available.
        - For LLM/Codex P0/P1 findings, require deterministic/harness corroboration.
          If not corroborated, downgrade to P2 advisory to avoid blocking on LLM-only claims.
        """
        files = ingest.get("files", []) if isinstance(ingest, dict) else []
        line_limits: dict[str, int] = {}
        for file_info in files:
            if not isinstance(file_info, dict):
                continue
            rel_path = file_info.get("path")
            if not isinstance(rel_path, str) or not rel_path:
                continue
            lines = file_info.get("lines")
            if isinstance(lines, int) and lines > 0:
                line_limits[rel_path.replace("\\", "/")] = lines
            else:
                line_limits[rel_path.replace("\\", "/")] = 1

        normalized: List[dict] = []
        for finding in llm_findings:
            if not isinstance(finding, dict):
                continue
            source = str(finding.get("source") or "llm").lower()
            path_raw = finding.get("file_path")
            if not isinstance(path_raw, str) or not path_raw:
                if source == "system":
                    path_raw = "<system>"
                else:
                    continue

            # Preserve synthetic/system findings generated by fail-closed paths.
            # These do not map to repository files by design.
            if source == "system":
                fixed = dict(finding)
                fixed["file_path"] = path_raw.replace("\\", "/")
                try:
                    fixed["line_start"] = int(finding.get("line_start") or 0)
                except (TypeError, ValueError):
                    fixed["line_start"] = 0
                try:
                    fixed["line_end"] = int(
                        finding.get("line_end") or fixed["line_start"]
                    )
                except (TypeError, ValueError):
                    fixed["line_end"] = fixed["line_start"]
                fixed["severity"] = str(finding.get("severity") or "P0")
                fixed["fix_plan"] = ensure_fix_plan(
                    fix_plan=finding.get("fix_plan", ""),
                    recommendation=finding.get("recommendation", ""),
                    message=finding.get("message", ""),
                )
                normalized.append(fixed)
                continue
            path = path_raw.replace("\\", "/")
            max_line = line_limits.get(path)
            if max_line is None:
                continue

            try:
                line_start = int(finding.get("line_start") or 1)
            except (TypeError, ValueError):
                line_start = 1
            try:
                line_end = int(finding.get("line_end") or line_start)
            except (TypeError, ValueError):
                line_end = line_start

            line_start = min(max(line_start, 1), max_line)
            line_end = min(max(line_end, line_start), max_line)

            severity = str(finding.get("severity") or "P3")
            category = str(finding.get("category") or "unknown")
            message = str(finding.get("message") or "")
            corroboration = None

            try:
                confidence = float(finding.get("confidence", 0.8))
            except (TypeError, ValueError):
                confidence = 0.8
            confidence = min(max(confidence, 0.0), 1.0)

            if source in {"llm", "codex"} and severity in {"P0", "P1"}:
                typed_candidate = _validated_typed_candidate_binding(finding)
                if not self._is_corroborated(
                    path,
                    line_start,
                    line_end,
                    category,
                    non_llm_findings,
                    typed_candidate=typed_candidate is not None,
                ):
                    canonical_category: str | None
                    if typed_candidate is None:
                        canonical_category = category
                        corroboration_reason = (
                            "no_compatible_deterministic_finding"
                        )
                    else:
                        canonical_category = _canonical_corroboration_category(category)
                        if canonical_category is None:
                            corroboration_reason = "unsupported_category"
                        elif canonical_category in _TYPED_CATEGORIES_REQUIRING_GENERATOR:
                            corroboration_reason = (
                                "no_reviewed_deterministic_producer"
                            )
                        else:
                            corroboration_reason = (
                                "no_compatible_deterministic_finding"
                            )
                    corroboration = {
                        "required": True,
                        "status": "missing",
                        "reason": corroboration_reason,
                        "canonical_category": canonical_category,
                    }
                    severity = "P2"
                    confidence = min(confidence, 0.75)
                    if message:
                        message = (
                            f"{message} (LLM-only, needs deterministic corroboration)"
                        )

            fixed = dict(finding)
            fixed["file_path"] = path
            fixed["line_start"] = line_start
            fixed["line_end"] = line_end
            fixed["severity"] = severity
            fixed["confidence"] = confidence
            fixed["message"] = message
            if corroboration is not None:
                fixed["corroboration"] = corroboration
            fixed["fix_plan"] = ensure_fix_plan(
                fix_plan=finding.get("fix_plan", ""),
                recommendation=finding.get("recommendation", ""),
                message=message,
            )
            normalized.append(fixed)

        return normalized

    def _is_corroborated(
        self,
        path: str,
        line_start: int,
        line_end: int,
        category: str,
        non_llm_findings: List[dict],
        *,
        typed_candidate: bool = False,
    ) -> bool:
        expected_category = (
            _canonical_corroboration_category(category)
            if typed_candidate
            else category
        )
        if typed_candidate:
            if (
                expected_category is None
                or expected_category in _TYPED_CATEGORIES_REQUIRING_GENERATOR
            ):
                return False
        elif not expected_category:
            return False
        expanded_start = max(1, line_start - 5)
        # Only source-bound TypeSafe candidates may use their reviewed span.
        # Generator line_end is model-controlled, so legacy corroboration stays
        # within the historical first-line window even if a huge end is forged.
        expanded_end = (line_end if typed_candidate else line_start) + 5
        for finding in non_llm_findings:
            if not isinstance(finding, dict):
                continue
            other_path = str(finding.get("file_path") or "").replace("\\", "/")
            if other_path != path:
                continue
            other_category = (
                _canonical_corroboration_category(finding.get("category"))
                if typed_candidate
                else str(finding.get("category") or "")
            )
            if other_category != expected_category:
                continue
            other_start = _coerce_finding_int(finding.get("line_start"))
            if other_start is None:
                continue
            other_end = _coerce_finding_int(
                finding.get("line_end") or other_start
            )
            if other_end is None:
                continue
            if other_start < 1 or other_end < other_start:
                continue
            if other_start <= expanded_end and other_end >= expanded_start:
                return True
        return False

    def _count_by_severity(self, findings: List[dict]) -> dict:
        """Count findings by severity."""
        counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "total": len(findings)}
        for finding in findings:
            sev = finding.get("severity", "P3")
            if sev in counts:
                counts[sev] += 1
        return counts

    def _identify_hotspots_with_findings(
        self, findings: List[dict], hotspots: dict
    ) -> List[str]:
        """Return hotspot files that have findings."""
        if not hotspots:
            return []
        hotspot_files = set()
        for files in hotspots.values():
            if isinstance(files, list):
                hotspot_files.update(files)
        if not hotspot_files:
            return []
        finding_files = {
            finding.get("file_path") for finding in findings if finding.get("file_path")
        }
        return sorted(hotspot_files.intersection(finding_files))

    def _finding_to_dict(self, finding) -> dict:
        """Convert Finding dataclass to dict."""
        recommendation = finding.recommendation
        return {
            "id": finding.id,
            "severity": finding.severity,
            "category": finding.category,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "snippet": finding.snippet,
            "message": finding.message,
            "recommendation": recommendation,
            "fix_plan": ensure_fix_plan(
                fix_plan=getattr(finding, "fix_plan", ""),
                recommendation=recommendation,
                message=finding.message,
            ),
            "confidence": finding.confidence,
            "source": finding.source,
        }

    def _parsed_finding_to_dict(self, finding: ParsedFinding) -> dict:
        """Convert ParsedFinding to dict."""
        recommendation = finding.recommendation
        return {
            "id": f"{finding.category}-{finding.file_path}-{finding.line_start}",
            "severity": finding.severity,
            "category": finding.category,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "snippet": "",
            "message": finding.message,
            "recommendation": recommendation,
            "fix_plan": ensure_fix_plan(
                fix_plan=finding.fix_plan,
                recommendation=recommendation,
                message=finding.message,
            ),
            "confidence": finding.confidence,
            "source": finding.source,
        }
