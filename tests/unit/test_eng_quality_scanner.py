from __future__ import annotations

from omargate.analyze.deterministic.eng_quality_scanner import EngQualityScanner


def test_frontend_rules_only_apply_to_react_projects() -> None:
    files = {
        "src/App.tsx": (
            "export const App = () => {\n"
            "  items.forEach(item => { setCount(item.count); });\n"
            "  return <div />;\n"
            "};\n"
        ),
    }

    react = EngQualityScanner(tech_stack=["React", "TypeScript"])
    react_findings = react.scan(files)
    assert any(f.pattern_id == "EQ-001" for f in react_findings)

    python = EngQualityScanner(tech_stack=["Python"])
    python_findings = python.scan(files)
    assert not any(f.pattern_id == "EQ-001" for f in python_findings)


def test_eval_detected_as_p0() -> None:
    files = {"src/server.js": "const out = eval(userInput);\n"}
    scanner = EngQualityScanner(tech_stack=["Node.js"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-008"), None)
    assert finding is not None
    assert finding.severity == "P0"


def test_eval_string_literal_not_flagged_in_python() -> None:
    files = {
        "src/rules.py": (
            "RULE = 'Use of eval() or Function() constructor can enable arbitrary code execution.'\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-008" for f in findings)


def test_eval_call_detected_in_python() -> None:
    files = {"src/app.py": "def run(user_input):\n    return eval(user_input)\n"}
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-008" for f in findings)


def test_python_fstring_sql_interpolation_detected_as_p0() -> None:
    files = {
        "src/query.py": (
            "def load(user_id):\n"
            '    return f"SELECT email FROM users WHERE id = {user_id}"\n'
        ),
        "src/lowercase.py": (
            'payload = f"select * from users where id = {user_id}"\n'
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    sql_findings = [finding for finding in findings if finding.pattern_id == "EQ-009"]
    assert {finding.file_path for finding in sql_findings} == {
        "src/lowercase.py",
        "src/query.py",
    }
    assert all(finding.severity == "P0" for finding in sql_findings)
    assert next(
        finding for finding in sql_findings if finding.file_path == "src/query.py"
    ).line_start == 2


def test_python_sql_string_concatenation_detected_as_p0() -> None:
    files = {"src/query.py": 'query = "DELETE FROM users WHERE id = " + user_id\n'}
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-009" and f.severity == "P0" for f in findings)


def test_javascript_sql_interpolation_detected_without_prose_false_positives() -> None:
    files = {
        "src/template.js": (
            "const query = `SELECT email FROM users WHERE id = ${userId}`;\n"
        ),
        "src/lowercase.ts": (
            "const query = `select email from users where id = ${userId}`;\n"
        ),
        "src/concat.js": (
            'const query = "DELETE FROM users WHERE id = " + userId;\n'
        ),
        "src/update-prose.js": (
            'const message = "Refusing to update DNS for " + hostname;\n'
        ),
        "src/select-prose.js": (
            'const message = "Please select a server for " + region;\n'
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Node.js"])

    findings = [
        finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-009"
    ]

    assert [finding.file_path for finding in findings] == [
        "src/concat.js",
        "src/lowercase.ts",
        "src/template.js",
    ]
    assert all(finding.severity == "P0" for finding in findings)


def test_python_sql_interpolation_preserves_supported_statement_variants() -> None:
    cases = {
        "select_expression": 'query = f"SELECT {user_expression}"\n',
        "select_alias": 'query = f"SELECT {value} AS result"\n',
        "select_arithmetic": 'query = f"SELECT 1 + {value}"\n',
        "select_case": (
            'query = f"SELECT CASE WHEN {condition} THEN 1 ELSE 0 END"\n'
        ),
        "select_function": 'payload = f"select pg_sleep({delay})"\n',
        "leading_comment": (
            'query = f"/* audit */ SELECT * FROM users WHERE id = {user_id}"\n'
        ),
        "sqlite_insert": (
            'query = f"INSERT OR IGNORE INTO users(id) VALUES ({user_id})"\n'
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    for name, source in cases.items():
        findings = scanner.scan({f"src/{name}.py": source})
        assert any(finding.pattern_id == "EQ-009" for finding in findings), name


def test_bare_dynamic_select_requires_query_context() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])

    query_findings = scanner.scan(
        {"src/query.py": 'query = f"SELECT {user_expression}"\n'}
    )
    prose_findings = scanner.scan(
        {"src/message.py": 'message = f"select {option}"\n'}
    )

    assert any(finding.pattern_id == "EQ-009" for finding in query_findings)
    assert not any(finding.pattern_id == "EQ-009" for finding in prose_findings)


def test_dynamic_select_tracks_direct_sink_without_broad_ancestry() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    files = {
        "src/executed.py": (
            'payload = f"SELECT {value} AS result"\n'
            "cursor.execute(payload)\n"
        ),
        "src/container.py": (
            'query = {"message": f"select {option}"}\n'
            "def build_query():\n"
            '    message = f"select {option}"\n'
        ),
    }

    findings = scanner.scan(files)
    sql_findings = [finding for finding in findings if finding.pattern_id == "EQ-009"]

    assert [(finding.file_path, finding.line_start) for finding in sql_findings] == [
        ("src/executed.py", 1)
    ]


def test_python_sql_concatenation_handles_large_expression_iteratively() -> None:
    source = (
        'query = "SELECT * FROM users WHERE id = " + '
        + " + ".join("user_id" for _ in range(999))
        + "\n"
    )
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan({"src/large_query.py": source})
    assert sum(finding.pattern_id == "EQ-009" for finding in findings) == 1


def test_dns_update_error_fstring_is_not_misclassified_as_sql() -> None:
    files = {
        "scripts/cloudflare/check_dashboard_dns_origin.py": (
            "raise DashboardDnsOriginError(\n"
            '    f"Refusing to update ambiguous DNS records for {hostname}; "\n'
            '    "clean them up explicitly."\n'
            ")\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-009" for f in findings)


def test_unparseable_python_uses_sql_anchored_fallback() -> None:
    files = {
        "src/broken.py": (
            'query = f"UPDATE users SET name = {name} WHERE id = {user_id}"\n'
            "this is invalid python\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-009" and f.line_start == 1 for f in findings)


def test_unparseable_python_fallback_handles_dynamic_select_variants() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    files = {
        "src/query.py": (
            'query = f"SELECT {user_expression}"\n'
            'payload = f"select pg_sleep({delay})"\n'
            'message = f"select {option}"\n'
            'sql = "SELECT " + user_expression\n'
            "this is invalid python\n"
        )
    }

    findings = scanner.scan(files)
    sql_lines = {
        finding.line_start for finding in findings if finding.pattern_id == "EQ-009"
    }

    assert sql_lines == {1, 2, 4}


def test_unparseable_python_recovers_call_return_and_dataflow_context() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    files = {
        "src/broken.py": (
            'cursor.execute(f"SELECT 1 + {value}")\n'
            'payload = f"SELECT {other_value} AS result"\n'
            "cursor.execute(payload)\n"
            "def build_query():\n"
            '    return f"SELECT {final_value}"\n'
            "this is invalid python\n"
        )
    }

    findings = scanner.scan(files)
    sql_lines = {
        finding.line_start for finding in findings if finding.pattern_id == "EQ-009"
    }

    assert sql_lines == {1, 2, 5}


def test_dockerfile_without_user_detected_as_p2() -> None:
    files = {"Dockerfile": "FROM python:3.11\nRUN echo hi\n"}
    scanner = EngQualityScanner(tech_stack=[])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-018"), None)
    assert finding is not None
    assert finding.severity == "P2"


def test_dockerfile_root_user_waiver_suppresses_finding() -> None:
    files = {
        "Dockerfile": (
            "FROM python:3.11\n"
            "# omargate:allow-root-user\n"
            "RUN echo hi\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=[])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-018" for f in findings)


def test_env_file_committed_detected_as_p0() -> None:
    files = {
        ".env": "".join(('OPENAI_API_KEY=sk', '-test\n')),
        ".env.example": "OPENAI_API_KEY=\n",
    }
    scanner = EngQualityScanner(tech_stack=[])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-020" and f.severity == "P0" for f in findings)


def test_n_plus_one_query_pattern_detected() -> None:
    files = {
        "src/app.py": (
            "async def f(user_ids, session):\n"
            "    for user_id in user_ids:\n"
            "        await session.execute(\"SELECT 1\", {\"id\": user_id})\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["FastAPI", "Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-007" for f in findings)


def test_multiline_httpx_client_with_explicit_timeout_is_not_flagged() -> None:
    files = {
        "src/routes/auth.py": (
            "async def fetch_metadata():\n"
            "    async with httpx.AsyncClient(\n"
            "        follow_redirects=False,\n"
            "        timeout=_CIMD_FETCH_TIMEOUT_S,\n"
            "    ) as client:\n"
            "        return await client.get('https://example.com')\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-012" for f in findings)


def test_multiline_httpx_client_without_timeout_is_flagged() -> None:
    files = {
        "src/routes/auth.py": (
            "async def fetch_metadata():\n"
            "    async with httpx.AsyncClient(\n"
            "        follow_redirects=False,\n"
            "    ) as client:\n"
            "        return await client.get('https://example.com')\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-012"), None)
    assert finding is not None
    assert finding.line_start == 2
    assert finding.line_end == 4


def test_multiline_httpx_get_with_explicit_timeout_is_not_flagged() -> None:
    files = {
        "src/client.py": (
            "async def fetch_metadata(url):\n"
            "    return await httpx.get(\n"
            "        url,\n"
            "        timeout=5.0,\n"
            "    )\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-012" for f in findings)


def test_timeout_text_in_comment_or_string_does_not_suppress_finding() -> None:
    files = {
        "src/comment.py": "client = httpx.Client(  # timeout inherited elsewhere\n)\n",
        "src/string.py": 'response = httpx.get("timeout")\n',
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert {finding.file_path for finding in findings} == {
        "src/comment.py",
        "src/string.py",
    }


def test_nested_timeout_argument_does_not_count_as_httpx_timeout() -> None:
    files = {
        "src/client.py": (
            "response = httpx.get(\n"
            "    build_url(timeout=5.0),\n"
            ")\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert len(findings) == 1
    assert findings[0].line_start == 1


def test_syntax_error_uses_balanced_call_fallback() -> None:
    files = {
        "src/client.py": (
            "bounded = httpx.get(\n"
            "    'https://example.com/bounded',\n"
            "    timeout=5.0,\n"
            ")\n"
            "unbounded = httpx.get(  # timeout is still missing\n"
            "    'https://example.com/unbounded',\n"
            ")\n"
            "def broken(:\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert [finding.line_start for finding in findings] == [5]


def test_one_line_httpx_call_without_timeout_is_flagged() -> None:
    files = {"src/client.py": "response = httpx.post('https://example.com')\n"}
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert len(findings) == 1
    assert findings[0].line_start == 1


def test_same_line_httpx_calls_emit_one_unique_finding() -> None:
    files = {
        "src/nested.py": "result = httpx.get(httpx.post('https://inner'))\n",
        "src/sequential.py": (
            "first = httpx.get('https://first'); "
            "second = httpx.post('https://second')\n"
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert len(findings) == 2
    assert len({finding.id for finding in findings}) == len(findings)
    assert {finding.file_path for finding in findings} == set(files)


def test_httpx_module_case_matching_preserves_existing_behavior() -> None:
    files = {
        "src/parseable.py": (
            "import httpx as HTTPX\n"
            "response = HTTPX.get('https://example.com')\n"
        ),
        "src/syntax_error.py": (
            "import httpx as HTTPX\n"
            "client = HTTPX.AsyncClient()\n"
            "def broken(:\n"
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert [(finding.file_path, finding.line_start) for finding in findings] == [
        ("src/parseable.py", 2),
        ("src/syntax_error.py", 2),
    ]


def _n_plus_one_lines(source: str) -> list[int]:
    scanner = EngQualityScanner(tech_stack=["FastAPI", "Python"])
    findings = scanner.scan({"src/service.py": source})
    return [f.line_start for f in findings if f.pattern_id == "EQ-007"]


def test_n_plus_one_still_flags_awaits_inside_the_loop_body() -> None:
    # Deep in the body, after a blank line and a nested block, and inside a
    # nested loop: every per-item await is still a finding, reported at the
    # outer for-line exactly as before.
    source = (
        "async def f(ids, db):\n"
        "    for item_id in ids:\n"
        "        if item_id:\n"
        "            label = str(item_id)\n"
        "\n"
        "            await db.execute(\"SELECT 1\", {\"id\": label})\n"
        "    return None\n"
        "\n"
        "async def g(groups, session):\n"
        "    for group in groups:\n"
        "        for member in group:\n"
        "            await session.get(member)\n"
    )
    assert _n_plus_one_lines(source) == [2, 10]


def test_n_plus_one_ignores_an_await_after_the_loop_ends() -> None:
    # One query, an in-memory loop, then ONE commit after the loop: not N+1.
    source = (
        "async def list_rows(self):\n"
        "    rows = (await self.db.scalars(stmt)).all()\n"
        "    for row in rows:\n"
        "        self._expire_if_due(row, now)\n"
        "    result = {\"rows\": [view(r) for r in rows]}\n"
        "    await self.db.commit()\n"
        "    return result\n"
    )
    assert _n_plus_one_lines(source) == []


def test_n_plus_one_ignores_a_batched_query_grouped_in_memory() -> None:
    source = (
        "async def list_links(self, links):\n"
        "    by_link = {link.id: [] for link in links}\n"
        "    if links:\n"
        "        rows = await self.db.scalars(select(Claim).where(Claim.link_id.in_(list(by_link))))\n"
        "        for claim in rows:\n"
        "            by_link[claim.link_id].append(claim)\n"
        "    metadata = []\n"
        "    for link in links:\n"
        "        metadata.append(len(by_link[link.id]))\n"
        "    await self.db.commit()\n"
        "    return metadata\n"
    )
    assert _n_plus_one_lines(source) == []


# (source, EQ-007 lines). All valid Python. Reviewer probe cases, 2026-09-30.
_LOOP_BODY_CASES = [
    # Comments, continuations and string contents never end a Python suite.
    ("async def f(ids, db):\n    for item in ids:\n# comment\n        await db.execute(item)\n", [2]),
    ("async def f(ids, db):\n    for item in ids:\n    # comment\n        await db.execute(item)\n", [2]),
    ("async def f(ids, db):\n    for item in ids:\n        statement = (\n\"SELECT 1\"\n        )\n        await db.execute(statement)\n", [2]),
    ("async def f(ids, db):\n    for item in ids:\n        statement = \"\"\"SELECT\n1\n\"\"\"\n        await db.execute(statement)\n", [2]),
    ("async def f(ids, db):\n    for item in ids:\n        await db.execute(\n            item\n        )\n", [2]),
    ("async def f(ids, db):\n    for item in ids:\n\n        if item:\n            await db.execute(item)\n", [2]),
    ("async def f(ids, db):\n    for item in ids:\n        await db.execute(item)\n", [2]),
    # Text that only looks like a loop is not one, in any case, and never crashes the scan.
    ('"""Pseudocode:\nFOR item in ids:\n    await db.execute(item)\n"""\n', []),
    ('"""Pseudocode:\nFor item in ids:\n    await db.execute(item)\n"""\n', []),
    # ...even beside a real loop elsewhere in the same file: only the real loop is reported.
    ('"""Pseudocode:\nFOR item in ids:\n    await db.execute(item)\n"""\nasync def f(ids, db):\n    for item in ids:\n        await db.execute(item)\n', [6]),
    # One await after the loop ends is not a per-item call, and neither is the else suite,
    # which runs once.
    ("async def f(ids, db):\n    for item in ids:\n        str(item)\n    await db.commit()\n", []),
    ("async def f(ids, db):\n    for item in ids:\n        str(item)\n    else:\n        await db.commit()\n", []),
    # Unchanged window: an await more than 800 chars into the body stays unreported, as before.
    ("async def f(ids, db):\n    for item in ids:\n" + "        pad = 1  # " + "x" * 800 + "\n        await db.execute(item)\n", []),
    # Unchanged pre-existing miss: the DB name is not on the await's own line.
    ("async def f(ids, db):\n    for item in ids:\n        await (\n            db.execute(item)\n        )\n", []),
]


def test_n_plus_one_loop_bodies_come_from_the_parser_not_indentation() -> None:
    for source, expected in _LOOP_BODY_CASES:
        compile(source, "<fixture>", "exec")  # valid Python; compiled, never run
        assert _n_plus_one_lines(source) == expected, source


def test_n_plus_one_on_unparsable_source_keeps_the_legacy_matcher() -> None:
    # A syntax error must neither crash the scan nor hide what the old rule reported.
    source = "async def f(ids, db):\n    for item in ids:\n        str(item)\n    await db.commit()\n    )\n"
    try:
        compile(source, "<fixture>", "exec")
    except SyntaxError:
        pass
    else:
        raise AssertionError("fixture must be invalid Python")
    assert _n_plus_one_lines(source) == [2]


def test_workflow_secret_labels_not_flagged_as_hardcoded_secrets() -> None:
    files = {
        ".github/workflows/security-review.yml": (
            "name: Security Review\n"
            "jobs:\n"
            "  secret-scanning:\n"
            "    name: Secret Scanning\n"
            "  upload:\n"
            "    name: Upload secret scan artifacts\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-021" for f in findings)


def test_workflow_hardcoded_secret_env_value_detected() -> None:
    files = {
        ".github/workflows/security-review.yml": (
            "jobs:\n"
            "  omar-review:\n"
            "    env:\n"
            "      OPENAI_API_KEY: " + "sk" + "_live_1234567890abcdef123456" + "\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-021" for f in findings)


def test_oidc_verify_aud_false_detected_as_p1() -> None:
    files = {
        "sentinelayer-api/src/auth/oidc_verifier.py": (
            "payload = jwt.decode(token, jwks, options={\"verify_aud\": False})\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-022"), None)
    assert finding is not None
    assert finding.severity == "P1"


def test_oauth_callback_missing_state_detected_as_p1() -> None:
    files = {
        "sentinelayer-api/src/routes/auth.py": (
            "class OAuthCallbackRequest(BaseModel):\n"
            "    code: str\n\n"
            "@router.post('/auth/github/callback')\n"
            "async def github_callback():\n"
            "    pass\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-023"), None)
    assert finding is not None
    assert finding.severity == "P1"


def test_missing_health_endpoint_uses_distinct_rule_id() -> None:
    files = {
        "sentinelayer-api/src/main.py": (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/auth/me')\n"
            "async def me():\n"
            "    return {'ok': True}\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-024"), None)
    assert finding is not None
    assert finding.severity == "P2"


def test_missing_request_id_rule_has_stack_specific_fix_plan() -> None:
    files = {
        "src/api.ts": (
            "export function handler(req, res) {\n"
            "  return res.status(500).json({ error: 'boom' });\n"
            "}\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Node.js"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-016"), None)
    assert finding is not None
    assert "requestId" in finding.fix_plan
    assert "Express" in finding.fix_plan


# EQ-009 and module-level string constants (sentinelayer-api migration 089, 2026-10-24). A migration that
# splices FIXED table/function/trigger names into DDL through module constants is not dynamic SQL; anything
# a caller, the environment or another scope can change must still be reported.
def _eq009_lines(source: str, path: str = "alembic/versions/089_example.py") -> list[int]:
    findings = EngQualityScanner(tech_stack=["Python", "FastAPI"]).scan({path: source})
    return sorted(f.line_start for f in findings if f.pattern_id == "EQ-009")


def test_eq009_module_constants_spliced_into_ddl_are_not_dynamic() -> None:
    source = (
        'SCHEDULE_TABLE = "session_admission_expiry_schedule"\n'
        'IMMEDIATE_DUE_SQL = "TIMESTAMPTZ \'1970-01-01 00:00:00+00\'"\n'
        'BACKFILL_SQL = f"""\n'
        "INSERT INTO {SCHEDULE_TABLE} (session_id, next_due_at)\n"
        "SELECT id, COALESCE(claim_deadline_at, {IMMEDIATE_DUE_SQL}) FROM session_admissions\n"
        '"""\n'
        'DELETE_SQL = "DELETE FROM " + SCHEDULE_TABLE + " WHERE next_due_at IS NULL"\n'
    )
    assert _eq009_lines(source) == []


def test_eq009_constant_built_from_earlier_constants_is_not_dynamic() -> None:
    source = (
        'PREFIX = "sentinelayer"\n'
        'TABLE = f"{PREFIX}_schedule"\n'
        'SQL = f"DELETE FROM {TABLE} WHERE id = 1"\n'
    )
    assert _eq009_lines(source) == []


def test_eq009_parameter_in_fstring_sql_is_still_reported() -> None:
    source = (
        'TABLE = "accounts"\n'
        "def load(user_id):\n"
        '    return f"SELECT * FROM {TABLE} WHERE id = {user_id}"\n'
    )
    assert _eq009_lines(source, "src/db.py") == [3]


def test_eq009_parameter_concatenated_into_sql_is_still_reported() -> None:
    source = (
        "def load(user_id):\n"
        '    return "DELETE FROM accounts WHERE id = " + user_id\n'
    )
    assert _eq009_lines(source, "src/db.py") == [2]


def test_eq009_constant_rebound_elsewhere_is_not_trusted() -> None:
    rebound_by_global = (
        'TABLE = "accounts"\n'
        "def retarget(name):\n"
        "    global TABLE\n"
        "    TABLE = name\n"
        'SQL = f"DELETE FROM {TABLE} WHERE id = 1"\n'
    )
    reassigned = (
        'TABLE = "accounts"\n'
        "TABLE = TABLE.upper()\n"
        'SQL = f"DELETE FROM {TABLE} WHERE id = 1"\n'
    )
    assert _eq009_lines(rebound_by_global) == [5]
    assert _eq009_lines(reassigned) == [3]


def test_eq009_non_literal_or_converted_constant_is_still_reported() -> None:
    from_env = (
        "import os\n"
        'TABLE = os.environ["TABLE"]\n'
        'SQL = f"DELETE FROM {TABLE} WHERE id = 1"\n'
    )
    converted = (
        'TABLE = "accounts"\n'
        'SQL = f"DELETE FROM {TABLE!r} WHERE id = 1"\n'
    )
    assert _eq009_lines(from_env) == [3]
    assert _eq009_lines(converted) == [2]


def test_eq009_parameter_shadowing_a_module_constant_is_still_reported() -> None:
    shadowed_by_parameter = (
        'TABLE = "accounts"\n'
        "def load(TABLE):\n"
        '    return f"DELETE FROM {TABLE} WHERE id = 1"\n'
    )
    shadowed_by_lambda = (
        'TABLE = "accounts"\n'
        'build = lambda TABLE: f"DELETE FROM {TABLE} WHERE id = 1"\n'
    )
    shadowed_by_kwonly = (
        'TABLE = "accounts"\n'
        "def load(*, TABLE):\n"
        '    return "DELETE FROM " + TABLE + " WHERE id = 1"\n'
    )
    assert _eq009_lines(shadowed_by_parameter, "src/db.py") == [3]
    assert _eq009_lines(shadowed_by_lambda, "src/db.py") == [2]
    assert _eq009_lines(shadowed_by_kwonly, "src/db.py") == [3]


def test_eq009_constants_are_trusted_only_at_module_level_without_wildcard_imports() -> None:
    wildcard = (
        'TABLE = "accounts"\n'
        "from dynamic_tables import *\n"
        'SQL = f"DELETE FROM {TABLE} WHERE id = 1"\n'
    )
    closure = (
        'TABLE = "accounts"\n'
        "def outer(TABLE):\n"
        "    def load():\n"
        '        return f"DELETE FROM {TABLE} WHERE id = 1"\n'
        "    return load\n"
    )
    inside_function = (
        'TABLE = "accounts"\n'
        "def load():\n"
        '    return f"DELETE FROM {TABLE} WHERE id = 1"\n'
    )
    assert _eq009_lines(wildcard) == [3]
    assert _eq009_lines(closure, "src/db.py") == [4]
    assert _eq009_lines(inside_function, "src/db.py") == [3]
