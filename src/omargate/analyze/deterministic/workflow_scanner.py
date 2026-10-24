"""Bounded YAML-aware workflow checks; source data is never executed.

GitHub's secure-use and workflow-dependency-lockfiles references, 2026-10-20.
Lock validation is structural; GitHub enforces locked repository identity at run time.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from ...redaction import sanitize_public_error
from .pattern_scanner import MAX_SCAN_BYTES, Finding, _truncate_snippet

_EXPRESSION = re.compile(r"\$\{\{([\s\S]*?)\}\}")
_CONTEXT_PATH = re.compile(r"(?<![\w'\"])\b(?:github|inputs)(?:\s*\.\s*\w+)+")
_UNTRUSTED_FIELDS = {"body", "default_branch", "description", "email", "head_branch", "head_commit", "head_ref", "ref_name", "label", "message", "name", "page_name", "ref", "title"}
_LEGACY_CONTEXT = re.compile(r"(?<![\w'\"])github\s*\.\s*event\s*\.\s*(?:issue|comment|review)\b")
_SAFE_EVENT_NUMBER = re.compile(r"github\.event\.(?:issue|comment|review)\.(?:id|number)$")
_EXECUTION_INPUTS = {"args", "arguments", "command", "commands", "entrypoint", "run", "script", "shell"}
_FULL_SHA = re.compile(r"[a-fA-F0-9]{40}")


class WorkflowInputIncomplete(ValueError):
    pass


def _document(text: str) -> Node:
    if len(text.encode("utf-8")) > MAX_SCAN_BYTES:
        raise WorkflowInputIncomplete("workflow_budget_exceeded")
    # Bound parser events and nesting before composing the graph. Compose uses
    # SafeLoader and never constructs Python objects or executes YAML tags.
    depth = events = 0
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        events += 1
        if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            depth += 1
        elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            depth -= 1
        if events > 20000 or depth > 64:
            raise WorkflowInputIncomplete("workflow_structure_budget_exceeded")
    node = yaml.compose(text, Loader=yaml.SafeLoader)
    if not isinstance(node, MappingNode):
        raise WorkflowInputIncomplete("workflow_mapping_required")
    return node


def _untrusted(expression: str) -> bool:
    normalized = re.sub(r"\[\s*['\"](\w+)['\"]\s*\]", r".\1", expression)
    normalized = re.sub(r"\[\s*(?:-?\d+|\*)\s*\]", "", normalized)
    normalized = re.sub(r"\.\s*\*\s*(?=\.|$)", "", normalized)
    for match in _CONTEXT_PATH.finditer(normalized):
        parts = re.sub(r"\s+", "", match.group(0)).split(".")
        if parts[0] == "inputs" or parts[:3] == ["github", "event", "inputs"]:
            return True
        if parts[0] == "github" and (parts[-1] in _UNTRUSTED_FIELDS or "tojson" in expression.lower()):
            return True
        # Preserve the legacy issue/comment/review coverage when a context field
        # is outside the structural vocabulary. Numeric API IDs are data, and a
        # quoted literal spelling a context path is not an actual context read.
        if _LEGACY_CONTEXT.match(match.group(0)) and not _SAFE_EVENT_NUMBER.fullmatch(".".join(parts)):
            return True
    return False


def _mapping(node: Node | None) -> dict[str, Node]:
    if not isinstance(node, MappingNode) or node.tag != "tag:yaml.org,2002:map":
        raise WorkflowInputIncomplete("workflow_mapping_required")
    result = {}
    for key, value in node.value:
        if not isinstance(key, ScalarNode) or key.value in result or key.value == "<<":
            raise WorkflowInputIncomplete("workflow_duplicate_or_merged_key")
        result[key.value] = value
    return result


def _scalar(node: Node | None) -> str:
    if not isinstance(node, ScalarNode) or not node.tag.startswith("tag:yaml.org,2002:"):
        raise WorkflowInputIncomplete("workflow_scalar_required")
    return node.value


def _locked(reference: str, workflow: str, lock: Node | None) -> bool:
    if lock is None:
        return False
    root = _mapping(lock)
    if _scalar(root.get("version")) != "v0.0.2":
        raise WorkflowInputIncomplete("unsupported_action_lock_version")
    workflows = _mapping(root.get("workflows"))
    registered = workflows.get(workflow)
    if registered is None:
        return False
    if not isinstance(registered, SequenceNode):
        raise WorkflowInputIncomplete("action_lock_workflow_invalid")
    if reference not in [_scalar(value) for value in registered.value]:
        return False
    dependencies = _mapping(root.get("dependencies"))
    record = _mapping(dependencies.get(reference))
    if _scalar(record.get("ref")) != reference.rsplit("@", 1)[-1]:
        raise WorkflowInputIncomplete("action_lock_ref_mismatch")
    if not re.fullmatch(r"sha1-[a-fA-F0-9]{40}", _scalar(record.get("commit"))):
        raise WorkflowInputIncomplete("action_lock_commit_invalid")
    for key in ("owner_id", "repo_id"):
        value = _scalar(record.get(key))
        if not value.isdecimal() or int(value) < 1:
            raise WorkflowInputIncomplete("action_lock_identity_invalid")
    return True


def _finding(rule: str, severity: str, path: str, node: Node | None, message: str, recommendation: str) -> Finding:
    line = node.start_mark.line + 1 if node is not None else 1
    end = max(line, node.end_mark.line + 1) if node is not None else line
    snippet = _scalar(node) if isinstance(node, ScalarNode) else ""
    return Finding(id=f"{rule}-{path}-{line}", pattern_id=rule, severity=severity,
                   category="ci-cd", file_path=path, line_start=line, line_end=end,
                   snippet=_truncate_snippet(sanitize_public_error(snippet)), message=message,
                   recommendation=recommendation, fix_plan=recommendation, confidence=1.0)


def scan_workflow(path: str, text: str, *, lock_text: str | None = None) -> list[Finding]:
    findings = []
    try:
        document = _mapping(_document(text))
        lock = _document(lock_text) if lock_text is not None else None
        if lock is not None:
            lock_root = _mapping(lock)
            if _scalar(lock_root.get("version")) != "v0.0.2":
                raise WorkflowInputIncomplete("unsupported_action_lock_version")
            _mapping(lock_root.get("workflows"))
            _mapping(lock_root.get("dependencies"))
        jobs = _mapping(document.get("jobs"))
        checked_targets = 0
        for job_node in jobs.values():
            job = _mapping(job_node)
            steps = job.get("steps")
            targets = [job]
            if steps is not None:
                if not isinstance(steps, SequenceNode) or len(steps.value) > 1000:
                    raise WorkflowInputIncomplete("workflow_steps_invalid")
                targets.extend(_mapping(step) for step in steps.value)
            for target in targets:
                checked_targets += 1
                if checked_targets > 4000:
                    raise WorkflowInputIncomplete("workflow_target_budget_exceeded")
                uses = target.get("uses")
                reference = _scalar(uses) if uses else ""
                if reference and not reference.startswith("./"):
                    pinned = bool(_FULL_SHA.fullmatch(reference.rsplit("@", 1)[-1]))
                    if reference.startswith("docker://"):
                        pinned = bool(re.search(r"@sha256:[a-fA-F0-9]{64}$", reference))
                    if not pinned and not _locked(reference, path, lock):
                        findings.append(_finding("CICD-002", "P2", path, uses,
                            "Action dependency is neither SHA-pinned nor covered by the workflow lockfile.",
                            "Pin to a full commit SHA or onboard this workflow with gh actions-lock and review the locked source identity."))
                scripts = [target["run"]] if "run" in target else []
                if reference.lower().startswith("actions/github-script@") and "with" in target:
                    script = _mapping(target["with"]).get("script")
                    if script is not None:
                        scripts.append(script)
                if "with" in target:
                    for key, value in _mapping(target["with"]).items():
                        text_value = _scalar(value)
                        if reference.startswith("docker://") and key.lower() in {"args", "entrypoint"}:
                            # Docker execution inputs reach the container directly;
                            # pinning the image cannot sanitize expression values.
                            scripts.append(value)
                            continue
                        if key == "script" and reference.lower().startswith("actions/github-script@"):
                            continue  # The known executable script gets the P0 check below.
                        if any(_untrusted(match.group(1)) for match in _EXPRESSION.finditer(text_value)):
                            executable = key.lower() in _EXECUTION_INPUTS
                            findings.append(_finding("CICD-ACTION-INPUT" if executable else "CICD-INPUT-FLOW",
                                "P2" if executable else "P4", path, value,
                                "Untrusted context reaches an execution-related action input; receiver review is required." if executable else
                                "Untrusted context is passed as action data; the receiving action owns validation.",
                                "Inspect the pinned receiving action's input contract, preserve argument boundaries, and avoid eval or string-built commands."))
                for script in scripts:
                    value = _scalar(script)
                    if any(_untrusted(expression.group(1)) for expression in _EXPRESSION.finditer(value)):
                        findings.append(_finding("CICD-001", "P0", path, script,
                            "Untrusted GitHub context reaches executable script text or a direct container execution input.",
                            "Pass untrusted context through an environment variable; quote variables, preserve argument boundaries, and never eval them."))
    except (WorkflowInputIncomplete, yaml.YAMLError, RecursionError, UnicodeError, ValueError):
        findings.append(_finding("CICD-COVERAGE-INCOMPLETE", "P1", path, None,
            "Workflow or dependency-lock evidence could not be completely analyzed.",
            "Repair invalid, unsupported or oversized workflow/lock structure and rerun; incomplete analysis is not a clean result."))
    return findings


def scan_workflow_files(files: list[dict], repo_root: Path) -> list[Finding]:
    findings = []
    lock_path = repo_root / ".github/workflows/actions.lock"
    lock_text = None
    lock_unreadable = False
    if lock_path.exists():
        try:
            if not lock_path.resolve().is_relative_to(repo_root.resolve()):
                raise ValueError("outside repository")
            with lock_path.open("rb") as handle:
                lock_bytes = handle.read(MAX_SCAN_BYTES + 1)
            if len(lock_bytes) > MAX_SCAN_BYTES:
                raise ValueError("oversize lock")
            lock_text = lock_bytes.decode("utf-8")
        except (OSError, ValueError, UnicodeError):
            lock_unreadable = True
    for record in files:
        path = str(record.get("path") or "").replace("\\", "/")
        if not path.startswith(".github/workflows/") or not path.endswith((".yml", ".yaml")):
            continue
        try:
            source = (repo_root / path).resolve()
            if not source.is_relative_to(repo_root.resolve()) or lock_unreadable:
                raise ValueError("unavailable workflow evidence")
            with source.open("rb") as handle:
                raw = handle.read(MAX_SCAN_BYTES + 1)
            if len(raw) > MAX_SCAN_BYTES:
                raise ValueError("oversize workflow")
            findings.extend(scan_workflow(path, raw.decode("utf-8"), lock_text=lock_text))
        except (OSError, ValueError, UnicodeError):
            findings.append(_finding("CICD-COVERAGE-INCOMPLETE", "P1", path, None,
                "Workflow source could not be completely read.", "Restore complete in-repository workflow and lock evidence before rerunning."))
    return findings
