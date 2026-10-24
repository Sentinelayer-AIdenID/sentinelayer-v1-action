#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

HITL_BANNER = (
    "> Generated stub. Human review required before publishing.\n"
    ">\n"
    "> This file is intentionally minimal to reduce documentation drift.\n"
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _write(path: Path, content: str, force: bool) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def _stubs() -> dict[Path, str]:
    return {
        Path("docs/ARCHITECTURE.md"): (
            "# Architecture\n\n"
            f"{HITL_BANNER}\n"
            "## Overview\n\n"
            "- What the system does\n"
            "- Trust boundaries (what leaves the runner)\n"
            "- Failure modes and fail-closed behavior\n\n"
            "## Data Flow\n\n"
            "1. Preflight (dedupe, fork policy, rate limit, cost approval)\n"
            "2. Ingest (repo map + hotspots)\n"
            "3. Deterministic scan\n"
            "4. LLM analysis\n"
            "5. Artifact write (FINDINGS.jsonl, PACK_SUMMARY.json, reports)\n"
            "6. Gate evaluation\n"
            "7. Publish (PR comment, Check Run)\n"
            "8. Telemetry upload (optional)\n"
        ),
        Path("docs/RUNBOOK.md"): (
            "# Runbook\n\n"
            f"{HITL_BANNER}\n"
            "## First Response Checklist\n\n"
            "- Confirm the failing check name and exit code\n"
            "- Inspect workflow logs and step summary\n"
            "- Review artifacts under `.sentinelayer/runs/<run_id>/`\n"
            "- Decide: fix findings, approve cost, adjust config, or bypass per policy\n\n"
            "## Common Scenarios\n\n"
            "- Gate blocked on P0/P1/P2 findings\n"
            "- Rate limited/cooldown\n"
            "- Cost approval required\n"
            "- Fork PR restrictions\n"
            "- Missing permissions for PR comments or Check Runs\n"
        ),
        Path("docs/ADRs/README.md"): (
            "# ADRs\n\n"
            f"{HITL_BANNER}\n"
            "Architecture Decision Records capture significant decisions.\n\n"
            "Use `docs/templates/ADR_TEMPLATE.md` as the starting point.\n"
        ),
        Path("docs/INCIDENTS/README.md"): (
            "# Incidents\n\n"
            f"{HITL_BANNER}\n"
            "Store incident reports here.\n\n"
            "Use `docs/templates/INCIDENT_TEMPLATE.md` as the starting point.\n"
        ),
        Path("docs/templates/ADR_TEMPLATE.md"): (
            "# ADR: <title>\n\n"
            f"{HITL_BANNER}\n"
            "## Status\n\n"
            "Proposed | Accepted | Deprecated | Superseded\n\n"
            "## Context\n\n"
            "What problem are we solving? What constraints exist?\n\n"
            "## Decision\n\n"
            "What did we decide?\n\n"
            "## Consequences\n\n"
            "What are the tradeoffs? What follow-up work is required?\n\n"
            "## Alternatives Considered\n\n"
            "- Option A\n"
            "- Option B\n"
        ),
        Path("docs/templates/RUNBOOK_TEMPLATE.md"): (
            "# Runbook: <system>\n\n"
            f"{HITL_BANNER}\n"
            "## Owner\n\n"
            "- Team:\n"
            "- On-call rotation:\n\n"
            "## Purpose\n\n"
            "What this runbook covers.\n\n"
            "## SLIs/SLOs\n\n"
            "- SLI:\n"
            "- SLO:\n\n"
            "## Alerting\n\n"
            "- Primary alerts:\n"
            "- Dashboards:\n\n"
            "## Triage\n\n"
            "1. Identify the failure mode\n"
            "2. Contain impact\n"
            "3. Mitigate\n"
            "4. Verify recovery\n\n"
            "## Rollback\n\n"
            "Rollback steps and safe defaults.\n\n"
            "## Postmortem\n\n"
            "When to write an incident report and required fields.\n"
        ),
        Path("docs/templates/INCIDENT_TEMPLATE.md"): (
            "# Incident: <title>\n\n"
            f"{HITL_BANNER}\n"
            "## Metadata\n\n"
            "| Field | Value |\n"
            "|---|---|\n"
            "| Incident ID | |\n"
            "| Severity | |\n"
            "| Status | |\n"
            "| Start (UTC) | |\n"
            "| End (UTC) | |\n"
            "| Incident Lead | |\n"
            "| Communications | |\n\n"
            "## Summary\n\n"
            "One-paragraph summary.\n\n"
            "## Impact\n\n"
            "Who/what was affected and how.\n\n"
            "## Detection\n\n"
            "How did we find out? What signals were missing?\n\n"
            "## Timeline (UTC)\n\n"
            "- 00:00 Event\n"
            "- 00:00 Mitigation\n\n"
            "## Root Cause\n\n"
            "What actually broke and why.\n\n"
            "## Resolution\n\n"
            "What fixed it.\n\n"
            "## Action Items\n\n"
            "- [ ] Prevent recurrence:\n"
            "- [ ] Improve detection:\n"
            "- [ ] Reduce MTTR:\n"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a minimal documentation set (stubs only).")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be created/overwritten")
    args = parser.parse_args(argv)

    repo_root = _repo_root()
    created: list[str] = []
    skipped: list[str] = []

    for rel, content in _stubs().items():
        path = repo_root / rel
        will_write = args.force or not path.exists()
        if args.dry_run:
            print(f"{'WRITE' if will_write else 'SKIP'} {rel.as_posix()}")
            continue
        if _write(path, content, force=args.force):
            created.append(rel.as_posix())
        else:
            skipped.append(rel.as_posix())

    if not args.dry_run:
        print("Minimal doc set generator")
        print()
        if created:
            print("Created/Updated")
            for p in created:
                print(f"- {p}")
        if skipped:
            print()
            print("Skipped (already exists)")
            for p in skipped:
                print(f"- {p}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

