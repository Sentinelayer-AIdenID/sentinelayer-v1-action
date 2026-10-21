from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, Optional

from .eng_quality_helpers import (
    index_to_line,
    is_test_file,
    line_snippet,
    python_eval_call_lines,
    python_httpx_calls,
    python_interpolated_sql_lines,
    strip_js_comments_and_strings,
    bounded_python_deadline_loops,
)
from .pattern_scanner import Finding, _truncate_snippet


_JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
_PY_EXTS = (".py",)
_GO_EXTS = (".go",)
_BACKEND_EXTS = _JS_EXTS + _PY_EXTS + _GO_EXTS

_JS_COMMENTS_AND_STRINGS_RE = re.compile(
    r"//[^\n]*|/\*[\s\S]*?\*/|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`",
    re.MULTILINE,
)


@dataclass(frozen=True)
class _Rule:
    pattern_id: str
    severity: str
    category: str
    message: str
    recommendation: str
    fix_plan: str


class EngQualityScanner:
    """Stack-aware engineering quality scanner."""

    def __init__(self, tech_stack: list[str]):
        self.tech_stack = [t.lower() for t in (tech_stack or [])]

    def scan(self, files: dict[str, str]) -> list[Finding]:
        """Scan file contents and return findings."""
        files = files or {}
        findings: list[Finding] = []

        if self._has_frontend():
            findings.extend(self._scan_frontend(files))
        if self._has_backend():
            findings.extend(self._scan_backend(files))
        findings.extend(self._scan_infrastructure(files))

        return findings

    def _has_frontend(self) -> bool:
        frontend_markers = ("react", "next.js", "nextjs", "vue", "angular")
        return any(any(marker in t for marker in frontend_markers) for t in self.tech_stack)

    def _has_backend(self) -> bool:
        backend_markers = ("node", "express", "django", "fastapi", "flask", "python", "go")
        return any(any(marker in t for marker in backend_markers) for t in self.tech_stack)

    def _scan_frontend(self, files: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_state_updates_in_loops(files))
        findings.extend(self._scan_useeffect_without_cleanup(files))
        # EQ-003 dangerouslySetInnerHTML: dropped (ESLint no-danger covers this)
        # EQ-004 inline JSX literals: dropped (ESLint jsx-no-bind territory)
        # EQ-005 console.log: dropped (ESLint no-console covers this)
        # EQ-006 useEffect empty deps: dropped (eslint-plugin-react-hooks exhaustive-deps)
        return findings

    def _scan_backend(self, files: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_n_plus_one(files))
        findings.extend(self._scan_eval_or_function_ctor(files))
        findings.extend(self._scan_sql_string_concat(files))
        # EQ-010 large timeouts: dropped (magic number variant, not gate-worthy)
        findings.extend(self._scan_auth_routes_without_rate_limit(files))
        findings.extend(self._scan_http_calls_without_timeout(files))
        findings.extend(self._scan_unbounded_retry_loops(files))
        findings.extend(self._scan_rate_limit_fail_open(files))
        findings.extend(self._scan_mutations_without_idempotency(files))
        findings.extend(self._scan_missing_request_id_schema(files))
        # EQ-017 external calls no fallback: dropped (0.35 confidence, too noisy)
        findings.extend(self._scan_oidc_verify_aud_disabled(files))
        findings.extend(self._scan_oauth_callback_missing_state(files))
        return findings

    def _scan_infrastructure(self, files: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_dockerfile_user(files))
        findings.extend(self._scan_terraform_remote_backend(files))
        findings.extend(self._scan_env_committed(files))
        findings.extend(self._scan_workflow_hardcoded_secrets(files))
        findings.extend(self._scan_missing_health_endpoint(files))
        return findings

    def _iter_files(
        self, files: dict[str, str], *, exts: Optional[tuple[str, ...]] = None
    ) -> Iterable[tuple[str, str]]:
        for path, content in sorted(files.items(), key=lambda kv: kv[0]):
            norm = path.replace("\\", "/")
            if exts is not None and not norm.lower().endswith(exts):
                continue
            yield norm, content or ""

    def _is_test_file(self, path: str) -> bool:
        return is_test_file(path)

    def _index_to_line(self, content: str, idx: int) -> int:
        return index_to_line(content, idx)

    def _line_snippet(self, content: str, line_start: int, line_end: int) -> str:
        return line_snippet(content, line_start, line_end)

    def _strip_js_comments_and_strings(self, content: str) -> str:
        return strip_js_comments_and_strings(content, _JS_COMMENTS_AND_STRINGS_RE)

    def _python_eval_call_lines(self, content: str) -> set[int]:
        return python_eval_call_lines(content)

    def _make_finding(
        self,
        rule: _Rule,
        *,
        file_path: str,
        line_start: int,
        line_end: Optional[int] = None,
        snippet: str = "",
        confidence: float = 0.8,
    ) -> Finding:
        le = line_end if isinstance(line_end, int) else line_start
        return Finding(
            id=f"{rule.pattern_id}-{file_path}-{line_start}",
            pattern_id=rule.pattern_id,
            severity=rule.severity,
            category=rule.category,
            file_path=file_path,
            line_start=line_start,
            line_end=le,
            snippet=snippet,
            message=rule.message,
            recommendation=rule.recommendation,
            fix_plan=rule.fix_plan,
            confidence=confidence,
            source="deterministic",
        )

    def _scan_state_updates_in_loops(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-001",
            severity="P4",
            category="frontend",
            message="Advisory: review repeated state replacements for stale-value intent; React batches updates.",
            recommendation="Verify the intended final state. React batches updates; functional updaters may intentionally compose queued changes. Do not infer a render count from setter calls.",
            fix_plan="Accumulate results in a local array/object and call the setter once after the loop. Example: replace items.forEach(... setRows(...)) with const nextRows = items.map(...); setRows(nextRows).",
        )
        regex = re.compile(
            r"\.(?:forEach|map)\s*\(\s*[^)]{0,400}=>[^)]{0,400}\b(setState|set[A-Z][A-Za-z0-9_]*)\s*\(",
            re.IGNORECASE | re.DOTALL,
        )
        findings: list[Finding] = []
        for path, content in self._iter_files(files, exts=_JS_EXTS):
            if ".d.ts" in path.lower():
                continue
            for m in regex.finditer(self._strip_js_comments_and_strings(content)):
                argument = content[m.end():].lstrip()
                if re.match(r"(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>", argument):
                    continue
                line = self._index_to_line(content, m.start())
                snippet = self._line_snippet(content, line, line)
                findings.append(
                    self._make_finding(rule, file_path=path, line_start=line, snippet=snippet, confidence=0.6)
                )
        return findings

    def _scan_useeffect_without_cleanup(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-002",
            severity="P2",
            category="frontend",
            message="useEffect appears to create a subscription/timer without a cleanup return.",
            recommendation="Return a cleanup function from useEffect (e.g., removeEventListener/clearInterval).",
            fix_plan="Return an explicit cleanup from the same useEffect that creates the resource. Example: const id = setInterval(...); return () => clearInterval(id); or unsubscribe() for subscriptions.",
        )
        findings: list[Finding] = []
        cleanup_re = re.compile(
            r"\breturn\s*\(\s*\)\s*=>|\breturn\s+function\b", re.IGNORECASE
        )
        trigger_re = re.compile(r"\b(addEventListener|setInterval|subscribe)\b", re.IGNORECASE)

        for path, content in self._iter_files(files, exts=(".jsx", ".tsx", ".ts", ".js")):
            if ".d.ts" in path.lower():
                continue
            lines = content.splitlines()
            for idx, line in enumerate(lines):
                if "useEffect" not in line:
                    continue
                if "useEffect" in line and "useEffect(" not in line:
                    continue
                block = "\n".join(lines[idx : min(idx + 60, len(lines))])
                if not trigger_re.search(block):
                    continue
                if cleanup_re.search(block):
                    continue
                line_no = idx + 1
                snippet = self._line_snippet(content, line_no, min(line_no + 8, line_no + 8))
                findings.append(
                    self._make_finding(
                        rule,
                        file_path=path,
                        line_start=line_no,
                        snippet=snippet,
                        confidence=0.7,
                    )
                )
        return findings

    def _scan_dangerously_set_inner_html(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-003",
            severity="P1",
            category="frontend",
            message="dangerouslySetInnerHTML can enable XSS if content is not strictly sanitized.",
            recommendation="Avoid raw HTML injection; if unavoidable, sanitize with a trusted sanitizer and document the source.",
            fix_plan="Replace raw HTML injection with escaped rendering when possible. If HTML is required, sanitize at assignment time (for example with DOMPurify) and render only sanitizedHtml in dangerouslySetInnerHTML.",
        )
        findings: list[Finding] = []
        for path, content in self._iter_files(files, exts=(".jsx", ".tsx", ".ts", ".js")):
            if "dangerouslysetinnerhtml" not in content.lower():
                continue
            for m in re.finditer(r"\bdangerouslySetInnerHTML\b", content):
                line = self._index_to_line(content, m.start())
                snippet = self._line_snippet(content, line, line)
                findings.append(
                    self._make_finding(
                        rule, file_path=path, line_start=line, snippet=snippet, confidence=0.9
                    )
                )
        return findings

    def _scan_inline_jsx_literals(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-004",
            severity="P3",
            category="frontend",
            message="Inline object/function literals in JSX props can cause unnecessary rerenders.",
            recommendation="Hoist literals outside render or wrap callbacks in useCallback/useMemo as appropriate.",
            fix_plan="Hoist inline objects/functions to stable references. Example: const onClick = useCallback(() => save(id), [id]); const style = useMemo(() => ({ color }), [color]); then pass onClick/style props.",
        )
        findings: list[Finding] = []
        obj_re = re.compile(r"=\s*\{\s*\{")
        fn_re = re.compile(r"=\s*\{\s*(?:\(\s*\)\s*=>|function\s*\()")
        max_per_file = 3  # Cap to avoid flooding reports

        for path, content in self._iter_files(files, exts=(".jsx", ".tsx")):
            lines = content.splitlines()
            file_count = 0
            for idx, line in enumerate(lines):
                if file_count >= max_per_file:
                    break
                if "<" not in line or "=" not in line or "{" not in line:
                    continue
                if obj_re.search(line) or fn_re.search(line):
                    line_no = idx + 1
                    snippet = _truncate_snippet(line.strip())
                    findings.append(
                        self._make_finding(
                            rule,
                            file_path=path,
                            line_start=line_no,
                            snippet=snippet,
                            confidence=0.6,
                        )
                    )
                    file_count += 1
        return findings

    def _scan_console_log(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-005",
            severity="P3",
            category="frontend",
            message="console.log left in production source can leak data and create noise.",
            recommendation="Remove console.log or guard behind a debug flag; keep logs structured and intentional.",
            fix_plan="Remove console.log from production paths and route diagnostics through your logger abstraction. If temporary debugging is needed, guard with an explicit debug flag and strip before merge.",
        )
        findings: list[Finding] = []
        max_per_file = 5  # Cap to avoid flooding reports
        for path, content in self._iter_files(files, exts=_JS_EXTS):
            if self._is_test_file(path):
                continue
            file_count = 0
            for m in re.finditer(r"\bconsole\.log\s*\(", content):
                if file_count >= max_per_file:
                    break
                line = self._index_to_line(content, m.start())
                snippet = self._line_snippet(content, line, line)
                findings.append(
                    self._make_finding(
                        rule, file_path=path, line_start=line, snippet=snippet, confidence=0.9
                    )
                )
                file_count += 1
        return findings

    def _scan_useeffect_empty_deps_outer_state(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-006",
            severity="P2",
            category="frontend",
            message="useEffect has an empty dependency array but appears to reference outer state.",
            recommendation="Add the referenced state/props to the dependency array or refactor to avoid stale closures.",
            fix_plan="Add every referenced state/prop to the dependency array or move mutable values to refs. Example: change useEffect(() => { sync(userId); }, []) to useEffect(() => { sync(userId); }, [userId]).",
        )
        findings: list[Finding] = []
        empty_deps_re = re.compile(r",\s*\[\s*\]\s*\)", re.IGNORECASE)
        state_decl_re = re.compile(
            r"\bconst\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*(set[A-Za-z0-9_]+)\s*\]\s*=\s*useState\b"
        )

        for path, content in self._iter_files(files, exts=(".jsx", ".tsx", ".ts", ".js")):
            if ".d.ts" in path.lower():
                continue
            state_vars = {m.group(1) for m in state_decl_re.finditer(content)}
            if not state_vars:
                continue
            lines = content.splitlines()
            for idx, line in enumerate(lines):
                if "useEffect" not in line:
                    continue
                if "useEffect(" not in line:
                    continue
                block = "\n".join(lines[idx : min(idx + 80, len(lines))])
                if not empty_deps_re.search(block):
                    continue
                if not any(re.search(rf"\b{re.escape(var)}\b", block) for var in state_vars):
                    continue
                line_no = idx + 1
                snippet = self._line_snippet(content, line_no, min(line_no + 10, line_no + 10))
                findings.append(
                    self._make_finding(
                        rule,
                        file_path=path,
                        line_start=line_no,
                        snippet=snippet,
                        confidence=0.65,
                    )
                )
        return findings

    # --------------------
    # Backend rules
    # --------------------

    def _scan_n_plus_one(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-007",
            severity="P1",
            category="backend",
            message="Possible N+1 query pattern: await inside loop with a likely DB call.",
            recommendation="Batch queries (IN clause), prefetch, or use ORM eager loading to avoid per-item DB calls.",
            fix_plan="Move DB access out of the loop and fetch rows in one query. Example: replace per-item await session.execute(...) with a single WHERE id IN (...) query, then map results by id in memory.",
        )
        findings: list[Finding] = []

        js_re = re.compile(
            r"for\s*\([^)]*\)\s*\{[^}]{0,1200}\bawait\b[^;]{0,200}\b(db|prisma|sequelize|knex|query|execute)\b",
            re.IGNORECASE | re.DOTALL,
        )
        py_re = re.compile(
            r"^\s*for\s+.+:\s*$[\s\S]{0,800}?\n\s+await\s+.*\b(db|session|cursor|query|execute|fetch)\b",
            re.IGNORECASE | re.MULTILINE,
        )

        for path, content in self._iter_files(files, exts=_BACKEND_EXTS):
            if self._is_test_file(path):
                continue
            if path.endswith(_JS_EXTS):
                for m in js_re.finditer(content):
                    line = self._index_to_line(content, m.start())
                    snippet = self._line_snippet(content, line, min(line + 6, line + 6))
                    findings.append(
                        self._make_finding(
                            rule,
                            file_path=path,
                            line_start=line,
                            snippet=snippet,
                            confidence=0.75,
                        )
                    )
            if path.endswith(_PY_EXTS):
                for m in py_re.finditer(content):
                    line = self._index_to_line(content, m.start())
                    snippet = self._line_snippet(content, line, min(line + 6, line + 6))
                    findings.append(
                        self._make_finding(
                            rule,
                            file_path=path,
                            line_start=line,
                            snippet=snippet,
                            confidence=0.75,
                        )
                    )
        return findings

    def _scan_eval_or_function_ctor(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-008",
            severity="P0",
            category="backend",
            message="Use of eval()/exec() or Function() constructor can enable arbitrary code execution.",
            recommendation="Remove eval/exec/Function; use safe parsers/validators and explicit logic.",
            fix_plan="Delete eval/exec/Function execution paths and replace with explicit parsing/dispatch. Example: parse JSON with a strict schema and route known commands via a whitelist map instead of dynamic code execution.",
        )
        findings: list[Finding] = []
        for path, content in self._iter_files(files, exts=_BACKEND_EXTS):
            if self._is_test_file(path):
                continue
            if path.endswith(_PY_EXTS):
                for line in sorted(self._python_eval_call_lines(content)):
                    snippet = self._line_snippet(content, line, line)
                    findings.append(
                        self._make_finding(
                            rule,
                            file_path=path,
                            line_start=line,
                            snippet=snippet,
                            confidence=0.95,
                        )
                    )
                continue

            # JS/TS: strip strings/comments before regex so we don't flag rule text/docs.
            if path.endswith(_JS_EXTS):
                regex = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(", re.IGNORECASE)
                scrubbed = self._strip_js_comments_and_strings(content)
                for m in regex.finditer(scrubbed):
                    line = self._index_to_line(scrubbed, m.start())
                    snippet = self._line_snippet(content, line, line)
                    findings.append(
                        self._make_finding(
                            rule,
                            file_path=path,
                            line_start=line,
                            snippet=snippet,
                            confidence=0.95,
                        )
                    )
                continue

            # Go and other backend files: conservative regex.
            regex = re.compile(r"\beval\s*\(", re.IGNORECASE)
            for m in regex.finditer(content):
                line = self._index_to_line(content, m.start())
                snippet = self._line_snippet(content, line, line)
                findings.append(
                    self._make_finding(
                        rule,
                        file_path=path,
                        line_start=line,
                        snippet=snippet,
                        confidence=0.8,
                    )
                )
        return findings

    def _scan_sql_string_concat(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-009",
            severity="P0",
            category="backend",
            message="SQL query appears to be built via string concatenation/interpolation.",
            recommendation="Use parameterized queries / prepared statements; never concatenate untrusted input into SQL.",
            fix_plan="Convert interpolated SQL into parameterized statements. Example: change f\"... WHERE id = {user_id}\" to \"... WHERE id = :id\" with params {\"id\": user_id}, then add a regression test with crafted input.",
        )
        findings: list[Finding] = []

        sql_prefix = (
            r"(?:SELECT\b[\s\S]{0,400}\bFROM\b|INSERT\s+INTO\b|DELETE\s+FROM\b|"
            r"UPDATE\s+[^\s;]+\s+SET\b|WITH\b[\s\S]{0,400}\bAS\s*\()"
        )
        js_concat = re.compile(
            rf"(['\"])\s*{sql_prefix}[\s\S]{{0,400}}?\1\s*\+\s*"
            r"[A-Za-z_$][A-Za-z0-9_$.]*",
            re.IGNORECASE,
        )
        js_template = re.compile(
            rf"`\s*{sql_prefix}[^`]{{0,800}}\$\{{[^}}]+\}}[^`]*`",
            re.IGNORECASE,
        )

        for path, content in self._iter_files(files, exts=_BACKEND_EXTS):
            if self._is_test_file(path):
                continue
            if path.endswith(_JS_EXTS):
                matches = [*js_concat.finditer(content), *js_template.finditer(content)]
                for m in sorted(matches, key=lambda match: match.start()):
                    line = self._index_to_line(content, m.start())
                    snippet = self._line_snippet(content, line, line)
                    findings.append(
                        self._make_finding(
                            rule,
                            file_path=path,
                            line_start=line,
                            snippet=snippet,
                            confidence=0.85,
                        )
                    )
            if path.endswith(_PY_EXTS):
                for line in sorted(python_interpolated_sql_lines(content)):
                    snippet = self._line_snippet(content, line, line)
                    findings.append(
                        self._make_finding(
                            rule,
                            file_path=path,
                            line_start=line,
                            snippet=snippet,
                            confidence=0.9,
                        )
                    )

        return findings

    def _scan_large_timeouts(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-010",
            severity="P3",
            category="backend",
            message="Large hardcoded timeout detected (>= 10s).",
            recommendation="Avoid magic numbers; use config and consider jitter/backoff where appropriate.",
            fix_plan="Extract timeout literals into named constants or config-backed values. Example: const CACHE_TTL_MS = 24 * 60 * 60 * 1000; and reuse CACHE_TTL_MS at call sites instead of raw numbers.",
        )
        findings: list[Finding] = []
        regex = re.compile(r"\bsetTimeout\s*\([^,]+,\s*(\d{5,})\s*\)", re.IGNORECASE)
        for path, content in self._iter_files(files, exts=_JS_EXTS):
            if self._is_test_file(path):
                continue
            for m in regex.finditer(content):
                line = self._index_to_line(content, m.start())
                snippet = self._line_snippet(content, line, line)
                findings.append(
                    self._make_finding(
                        rule,
                        file_path=path,
                        line_start=line,
                        snippet=snippet,
                        confidence=0.75,
                    )
                )
        return findings

    def _scan_auth_routes_without_rate_limit(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-011",
            severity="P1",
            category="backend",
            message="Auth route handler appears to be missing rate limiting middleware.",
            recommendation="Add rate limiting on auth endpoints (login/register/password reset) and fail closed on errors.",
            fix_plan="Insert rate limiter middleware/dependency in the auth route chain before handler logic. Example: Express app.post('/login', limiter, loginHandler) or FastAPI dependency that enforces per-IP/per-account limits.",
        )
        findings: list[Finding] = []
        route_re = re.compile(
            r"\b(app|router)\.(post|get|put|patch|delete)\(\s*['\"][^'\"]*(login|signin|auth)[^'\"]*['\"]\s*,",
            re.IGNORECASE,
        )
        for path, content in self._iter_files(files, exts=_JS_EXTS):
            if self._is_test_file(path):
                continue
            for idx, line in enumerate(content.splitlines()):
                if not route_re.search(line):
                    continue
                if re.search(r"\b(rateLimit|limiter)\b", line):
                    continue
                # If the file configures a limiter elsewhere, avoid a noisy false positive.
                if re.search(r"\b(rateLimit|limiter)\b", content):
                    continue
                line_no = idx + 1
                snippet = _truncate_snippet(line.strip())
                findings.append(
                    self._make_finding(
                        rule,
                        file_path=path,
                        line_start=line_no,
                        snippet=snippet,
                        confidence=0.6,
                    )
                )
        return findings

    def _scan_http_calls_without_timeout(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-012",
            severity="P2",
            category="backend",
            message="Network call appears to be missing an explicit timeout.",
            recommendation="Set timeouts on all outbound calls (client defaults are often unsafe); for fetch use AbortController/signal.",
            fix_plan="Set explicit timeout values on every outbound client and centralize defaults. Example: axios.get(url, { timeout: HTTP_TIMEOUT_MS }) or httpx.AsyncClient(timeout=httpx.Timeout(10.0)); for fetch, wire AbortController.",
        )
        findings: list[Finding] = []

        axios_re = re.compile(r"\baxios\.(get|post|put|patch|delete)\s*\(", re.IGNORECASE)
        fetch_re = re.compile(r"\bfetch\s*\(", re.IGNORECASE)

        for path, content in self._iter_files(files, exts=_BACKEND_EXTS):
            if self._is_test_file(path):
                continue
            lines = content.splitlines()

            if path.endswith(_JS_EXTS):
                has_abort_controller = "abortcontroller" in content.lower()
                for idx, line in enumerate(lines):
                    if axios_re.search(line):
                        if "timeout" in line.lower():
                            continue
                        line_no = idx + 1
                        findings.append(
                            self._make_finding(
                                rule,
                                file_path=path,
                                line_start=line_no,
                                snippet=_truncate_snippet(line.strip()),
                                confidence=0.65,
                            )
                        )
                    if fetch_re.search(line):
                        if "signal" in line.lower() or has_abort_controller:
                            continue
                        line_no = idx + 1
                        findings.append(
                            self._make_finding(
                                rule,
                                file_path=path,
                                line_start=line_no,
                                snippet=_truncate_snippet(line.strip()),
                                confidence=0.55,
                            )
                        )

            if path.endswith(_PY_EXTS):
                reported_lines: set[int] = set()
                for call in python_httpx_calls(content):
                    if call.has_timeout or call.line_start in reported_lines:
                        continue
                    is_client = call.function_name in {"httpx.AsyncClient", "httpx.Client"}
                    findings.append(
                        self._make_finding(
                            rule,
                            file_path=path,
                            line_start=call.line_start,
                            line_end=call.line_end,
                            snippet=self._line_snippet(content, call.line_start, call.line_end),
                            confidence=0.6 if is_client else 0.7,
                        )
                    )
                    reported_lines.add(call.line_start)

        return findings

    def _scan_unbounded_retry_loops(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-013",
            severity="P1",
            category="backend",
            message="Potential unbounded retry loop detected.",
            recommendation="Add a max retry count and exponential backoff; surface failures with actionable errors.",
            fix_plan="Bound retries with max attempts and exponential backoff, then fail with context. Example: for attempt in range(MAX_RETRIES): ... sleep(BASE_MS * 2**attempt); after final attempt, raise typed error.",
        )
        findings: list[Finding] = []

        while_true_re = re.compile(
            r"^\s*(while\s*\(\s*true\s*\)|while\s+True)\b", re.IGNORECASE
        )
        bounded_re = re.compile(r"\b(max_attempts|max_retries|attempts?\s*<)\b", re.IGNORECASE)
        sleep_re = re.compile(r"\b(sleep|setTimeout)\b", re.IGNORECASE)

        for path, content in self._iter_files(files, exts=_BACKEND_EXTS):
            if self._is_test_file(path):
                continue
            deadline_bounded = bounded_python_deadline_loops(content) if path.endswith(".py") else set()
            lines = content.splitlines()
            for idx, line in enumerate(lines):
                if not while_true_re.search(line):
                    continue
                if idx + 1 in deadline_bounded:
                    continue
                window = "\\n".join(lines[idx : min(idx + 40, len(lines))])
                if bounded_re.search(window):
                    continue
                if not sleep_re.search(window):
                    continue
                line_no = idx + 1
                snippet = self._line_snippet(content, line_no, min(line_no + 10, line_no + 10))
                findings.append(
                    self._make_finding(
                        rule,
                        file_path=path,
                        line_start=line_no,
                        snippet=snippet,
                        confidence=0.6,
                    )
                )

        return findings

    def _scan_rate_limit_fail_open(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-014",
            severity="P1",
            category="backend",
            message="Rate limiting appears to fail open on errors.",
            recommendation="Fail closed on limiter errors (block/slow requests) or use a safe fallback strategy.",
            fix_plan="Change limiter error handling from allow to deny/degrade mode. Example: on limiter backend error, return 429 or enforce conservative in-memory throttling until the limiter recovers.",
        )
        findings: list[Finding] = []

        likely_limiter_file_re = re.compile(r"\brate\s*limit|\blimiter\b", re.IGNORECASE)
        fail_open_re = re.compile(
            r"catch\s*\([^)]*\)\s*\{[^}]{0,200}return\s+(true|next\s*\(\))",
            re.IGNORECASE | re.DOTALL,
        )

        for path, content in self._iter_files(files, exts=_JS_EXTS):
            if self._is_test_file(path):
                continue
            if not likely_limiter_file_re.search(content):
                continue
            for m in fail_open_re.finditer(content):
                line = self._index_to_line(content, m.start())
                snippet = self._line_snippet(content, line, min(line + 6, line + 6))
                findings.append(
                    self._make_finding(
                        rule,
                        file_path=path,
                        line_start=line,
                        snippet=snippet,
                        confidence=0.65,
                    )
                )

        return findings

    def _scan_mutations_without_idempotency(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-015",
            severity="P2",
            category="backend",
            message="Mutation endpoint may be missing idempotency key handling.",
            recommendation="Support Idempotency-Key (or equivalent) for write endpoints to make retries safe.",
            fix_plan="Require Idempotency-Key on create/update endpoints, persist request hash + response, and replay prior response for duplicate keys. Reject key reuse when payload hash differs to prevent semantic conflicts.",
        )
        findings: list[Finding] = []
        if "idempotency" in " ".join(self.tech_stack):
            return []

        node_route_re = re.compile(
            r"\b(app|router)\.(post|put|patch)\(\s*['\"][^'\"]*(create|order|payment|charge)[^'\"]*['\"]",
            re.IGNORECASE,
        )
        py_route_re = re.compile(
            r"^\s*@\w+\.((post|put|patch))\(\s*['\"][^'\"]*(create|order|payment|charge)[^'\"]*['\"]",
            re.IGNORECASE | re.MULTILINE,
        )

        for path, content in self._iter_files(files, exts=_BACKEND_EXTS):
            if self._is_test_file(path):
                continue
            if "idempotency" in content.lower() or "idempotency-key" in content.lower():
                continue

            if path.endswith(_JS_EXTS):
                for idx, line in enumerate(content.splitlines()):
                    if not node_route_re.search(line):
                        continue
                    findings.append(
                        self._make_finding(
                            rule,
                            file_path=path,
                            line_start=idx + 1,
                            snippet=_truncate_snippet(line.strip()),
                            confidence=0.5,
                        )
                    )
            if path.endswith(_PY_EXTS):
                for m in py_route_re.finditer(content):
                    line = self._index_to_line(content, m.start())
                    snippet = self._line_snippet(content, line, line)
                    findings.append(
                        self._make_finding(
                            rule,
                            file_path=path,
                            line_start=line,
                            snippet=snippet,
                            confidence=0.5,
                        )
                    )

        return findings

    def _scan_missing_request_id_schema(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-016",
            severity="P3",
            category="backend",
            message="Error responses may be missing a consistent requestId field.",
            recommendation="Include a requestId/correlationId in all error responses and logs for traceability.",
            fix_plan="Standardize an error envelope that always includes requestId and propagate it from middleware. Example: Express sets req.id from X-Request-ID or uuid(), and error responses include { error, requestId: req.id }.",
        )
        findings: list[Finding] = []
        error_marker_re = re.compile(r"\b(error|exception)\b", re.IGNORECASE)
        request_id_re = re.compile(
            r"\b(requestId|request_id|correlationId|traceId)\b", re.IGNORECASE
        )

        for path, content in self._iter_files(files, exts=_BACKEND_EXTS):
            if self._is_test_file(path):
                continue
            # JSX/TSX files are frontend UI components, not backend API handlers.
            if path.lower().endswith((".tsx", ".jsx")):
                continue
            if not error_marker_re.search(content):
                continue
            if request_id_re.search(content):
                continue
            # Reduce noise: once per file.
            findings.append(
                self._make_finding(rule, file_path=path, line_start=1, snippet="", confidence=0.4)
            )
        return findings

    def _scan_external_calls_without_fallback(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-017",
            severity="P2",
            category="backend",
            message="External service calls detected without an obvious circuit breaker or fallback.",
            recommendation="Add circuit breaker/fallback patterns for external dependencies and handle partial outages safely.",
            fix_plan="Wrap external calls in a circuit breaker with timeout, retry budget, and fallback behavior. Example: return cached/default response on open circuit and emit telemetry so partial outages do not cascade.",
        )
        findings: list[Finding] = []
        call_re = re.compile(r"\b(fetch\s*\(|axios\.|httpx\.)", re.IGNORECASE)
        has_resilience_re = re.compile(r"\b(circuit|fallback|breaker)\b", re.IGNORECASE)

        for path, content in self._iter_files(files, exts=_BACKEND_EXTS):
            if self._is_test_file(path):
                continue
            if not call_re.search(content):
                continue
            if has_resilience_re.search(content):
                continue
            findings.append(
                self._make_finding(rule, file_path=path, line_start=1, snippet="", confidence=0.35)
            )
        return findings

    # --------------------
    def _scan_dockerfile_user(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-018",
            severity="P2",
            category="infrastructure",
            message="Dockerfile does not specify a non-root USER.",
            recommendation="Add a non-root user and set USER to reduce container blast radius.",
            fix_plan="Create a dedicated non-root user/group in the Dockerfile and switch before runtime. Example: RUN addgroup -S app && adduser -S app -G app; USER app; then verify file ownership for writable paths.",
        )
        findings: list[Finding] = []
        waiver_re = re.compile(r"omargate:\s*allow-root-user", re.IGNORECASE)
        for path, content in self._iter_files(files):
            if path.lower().endswith("/dockerfile") or path.lower() == "dockerfile":
                if waiver_re.search(content):
                    continue
                has_user = any(
                    ln.strip().upper().startswith("USER ")
                    for ln in content.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                )
                if has_user:
                    continue
                findings.append(
                    self._make_finding(rule, file_path=path, line_start=1, snippet="", confidence=0.9)
                )
        return findings

    def _scan_oidc_verify_aud_disabled(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-022",
            severity="P1",
            category="auth",
            message="OIDC token verification appears to disable audience checks (verify_aud: False).",
            recommendation="Validate token audience explicitly to prevent accepting tokens minted for other audiences.",
            fix_plan="Enable audience verification in token decode/verify config and pin accepted audiences. Example: jwt.decode(..., audience=EXPECTED_AUD, options={\"verify_aud\": True}) with EXPECTED_AUD from trusted config.",
        )
        findings: list[Finding] = []
        regex = re.compile(r"[\"']?verify_aud[\"']?\s*[:=]\s*False")
        for path, content in self._iter_files(files, exts=_PY_EXTS):
            norm = path.lower()
            if "/auth/" not in norm and "oidc" not in norm:
                continue
            for match in regex.finditer(content):
                line = self._index_to_line(content, match.start())
                snippet = self._line_snippet(content, line, line)
                findings.append(
                    self._make_finding(
                        rule,
                        file_path=path,
                        line_start=line,
                        snippet=snippet,
                        confidence=0.95,
                    )
                )
        return findings

    def _scan_oauth_callback_missing_state(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-023",
            severity="P1",
            category="auth",
            message="OAuth callback request model appears to miss a state field validation.",
            recommendation="Require and verify OAuth state to prevent CSRF/login swapping attacks.",
            fix_plan="Add required state to callback schema and compare against server-side nonce/session value before exchanging code. Reject callbacks with missing/mismatched state and log requestId for traceability.",
        )
        findings: list[Finding] = []
        class_re = re.compile(r"class\s+OAuthCallbackRequest\s*\(\s*BaseModel\s*\)\s*:")
        field_code_re = re.compile(r"^\s*code\s*:\s*str\s*$", re.MULTILINE)
        field_state_re = re.compile(r"^\s*state\s*:\s*str\s*$", re.MULTILINE)

        for path, content in self._iter_files(files, exts=_PY_EXTS):
            norm = path.lower()
            if "auth" not in norm:
                continue
            if "/auth/github/callback" not in content:
                continue
            class_match = class_re.search(content)
            if not class_match:
                continue
            window = content[class_match.start() : class_match.start() + 800]
            if not field_code_re.search(window):
                continue
            if field_state_re.search(window):
                continue
            line = self._index_to_line(content, class_match.start())
            snippet = self._line_snippet(content, line, min(line + 8, line + 8))
            findings.append(
                self._make_finding(
                    rule,
                    file_path=path,
                    line_start=line,
                    snippet=snippet,
                    confidence=0.9,
                )
            )
        return findings

    def _scan_terraform_remote_backend(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-019",
            severity="P2",
            category="infrastructure",
            message="Terraform configuration may be missing a remote backend block.",
            recommendation="Configure a remote backend (e.g., S3/GCS/Azure) with encryption and locking to protect state.",
            fix_plan="Add a terraform backend block that uses remote state storage with locking and encryption. Example: backend \"s3\" with bucket/key/region plus DynamoDB lock table, then run terraform init -migrate-state.",
        )
        tf_files = [(p, c) for p, c in self._iter_files(files) if p.lower().endswith(".tf")]
        if not tf_files:
            return []
        combined = "\n".join(c for _, c in tf_files)
        backend_re = re.compile(
            r"terraform\s*\{[\s\S]{0,2000}backend\s+\"[^\"]+\"",
            re.IGNORECASE,
        )
        if backend_re.search(combined):
            return []
        first_path = tf_files[0][0]
        return [
            self._make_finding(rule, file_path=first_path, line_start=1, snippet="", confidence=0.7)
        ]

    def _scan_env_committed(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-020",
            severity="P0",
            category="infrastructure",
            message="A real .env file appears to be committed to the repository.",
            recommendation="Remove .env from version control, rotate any secrets, and commit only .env.example/.env.template.",
            fix_plan="Remove tracked .env from git history/current tree, rotate exposed credentials immediately, and enforce ignore rules. Keep only .env.example with placeholders and add a CI check that blocks committed .env files.",
        )
        findings: list[Finding] = []
        for path, _content in self._iter_files(files):
            p = path.lower()
            if not (p == ".env" or p.endswith("/.env")):
                continue
            if p.endswith(".env.example") or p.endswith(".env.template") or p.endswith(".env.sample"):
                continue
            findings.append(
                self._make_finding(rule, file_path=path, line_start=1, snippet="", confidence=0.95)
            )
        return findings

    def _scan_workflow_hardcoded_secrets(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-021",
            severity="P0",
            category="infrastructure",
            message="CI/CD workflow appears to contain hardcoded secrets.",
            recommendation="Move secrets to GitHub Secrets/OIDC and reference them via ${{ secrets.* }}; rotate exposed keys.",
            fix_plan="Replace hardcoded workflow secret values with GitHub Secrets or OIDC-issued credentials, then rotate any exposed values. Example: env: API_KEY: ${{ secrets.API_KEY }} and remove plaintext literals from workflow YAML.",
        )
        findings: list[Finding] = []
        secret_key_re = re.compile(r"(?:^|_)(token|secret|password|api[_-]?key)(?:$|_)", re.IGNORECASE)
        yaml_pair_re = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.+?)\s*$")
        for path, content in self._iter_files(files, exts=(".yml", ".yaml")):
            if not path.lower().startswith(".github/workflows/"):
                continue
            for idx, line in enumerate(content.splitlines()):
                m = yaml_pair_re.match(line)
                if not m:
                    continue
                key = m.group(1).strip()
                if not secret_key_re.search(key):
                    continue

                raw_val = m.group(2).strip().strip("'\"")
                if not raw_val:
                    continue
                if raw_val.startswith("${{"):
                    continue
                if raw_val.startswith("$"):
                    continue
                lowered = raw_val.lower()
                if lowered in {"true", "false", "null", "~"}:
                    continue
                if len(raw_val) < 8:
                    continue
                line_no = idx + 1
                # Don't include snippet to avoid leaking secrets.
                findings.append(
                    self._make_finding(rule, file_path=path, line_start=line_no, snippet="", confidence=0.9)
                )
        return findings

    def _scan_missing_health_endpoint(self, files: dict[str, str]) -> list[Finding]:
        rule = _Rule(
            pattern_id="EQ-024",
            severity="P2",
            category="infrastructure",
            message="No obvious health check endpoint detected in server code.",
            recommendation="Add a /health (and optionally /ready) endpoint returning minimal status for deploy orchestration.",
            fix_plan="Implement lightweight liveness/readiness routes and wire them to deployment probes. Example: GET /health returns 200 with build/version, and GET /ready verifies critical dependencies with bounded timeouts.",
        )
        # Only enforce if we see likely server code.
        server_signal_re = re.compile(
            r"(FastAPI\s*\(|express\s*\(|@app\.(get|post)\s*\(|router\.(get|post)\s*\()",
            re.IGNORECASE,
        )
        health_re = re.compile(
            r"['\"]/((\bhealthz?\b|\bready\b|\blive\b|\bstatus\b))['\"]",
            re.IGNORECASE,
        )

        backend_files = [
            (p, c)
            for p, c in self._iter_files(files, exts=_BACKEND_EXTS)
            if not self._is_test_file(p)
        ]
        if not backend_files:
            return []

        combined = "\n".join(c for _, c in backend_files)
        if not server_signal_re.search(combined):
            return []
        if health_re.search(combined):
            return []

        # Attribute to the most likely server entry file.
        preferred: Optional[str] = None
        for p, c in backend_files:
            if re.search(r"(app|server|main)\.(py|ts|js|go)$", p, re.IGNORECASE):
                preferred = p
                break
            if server_signal_re.search(c):
                preferred = p
                break

        return [
            self._make_finding(
                rule,
                file_path=preferred or backend_files[0][0],
                line_start=1,
                snippet="",
                confidence=0.55,
            )
        ]
