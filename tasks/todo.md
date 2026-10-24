# PR127 exact-diff and audited-lock repair

- [x] Add failing tests for a receipt-backed 1.2 MiB npm lock and mutation custody.
- [x] Add failing Git-backed tests for full two-hunk diff, omitted later hunk, oversize diff, and mismatched checkout head.
- [x] Permit receipt-backed npm locks through an explicit 10 MiB file bound while retaining the 1 MiB candidate bound.
- [x] Derive the typed PR review diff from event base/head commits, with bounded fetch and byte cap; fail closed when the exact graph or checkout cannot be verified.
- [x] Wire the attested diff into the typed PR scan path and checkout the event head in the action workflow.
- [x] Fail closed on legacy TypeSafe generator fallback when an audited lock exclusion cannot be retained.
- [x] Run focused and adjacent tests, lint, inspect exact diff, and report the child head and remaining limitations.

## Review

Fail-first probes on 4052a38 reproduced a 1.2 MiB audited npm lock rejected before its receipt and a real two-hunk Git patch accepted after the second hunk was omitted. The child repair now permits a receipt-verified npm lock up to 10 MiB while preserving the 1 MiB candidate limit. Typed PR scans compare the fetched GitHub patch to a locally generated, bounded diff from the event's exact base/head; shallow history is fetched to depth 128 with a 45-second timeout, and missing history, a wrong checkout head, mismatched hunks, or an oversized patch hold review. The action workflow checks out the event head. Legacy TypeSafe fallback holds when it would reintroduce an audited lockfile into whole-file generator context.

Focused repaired regressions: 7 passed. Full unit suite with `PYTHONPATH=src`: 1674 passed, 1 skipped in 149.37 seconds. Ruff and `git diff --check` passed. The earlier full run without PYTHONPATH had only two subprocess import failures; both passed after setting the path. Remaining policy scope: gate.py requires a live LLM attempt, so an audited-lock-only PR still holds until a separately reviewed deterministic audit-only gate path exists. External composite-action callers must check out the event PR head; a synthetic merge checkout now holds explicitly.
