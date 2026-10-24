from __future__ import annotations

import json
from pathlib import Path

DEFAULT_MAX_CONTEXT_TOKENS = 80000


class PromptLoader:
    """Load prompts from manifest. Prompts are injected at build time."""

    def __init__(self, prompts_dir: Path) -> None:
        self.prompts_dir = prompts_dir
        self.manifest = self._load_manifest()

    def _load_manifest(self) -> dict:
        manifest_path = self.prompts_dir / "manifest.json"
        if not manifest_path.exists():
            return {
                "schema_version": "1.0",
                "prompts": {},
                "default_prompt": None,
            }
        return json.loads(manifest_path.read_text(encoding="utf-8"))

    def _select_prompt_entry(self, name: str | None, scan_mode: str) -> dict | None:
        prompts = self.manifest.get("prompts") or {}
        if not prompts:
            return None

        def compatible(entry: dict) -> bool:
            modes = entry.get("scan_modes") or []
            return not modes or scan_mode in modes

        if name:
            entry = prompts.get(name)
            if entry and compatible(entry):
                return entry

        default_name = self.manifest.get("default_prompt")
        if default_name:
            entry = prompts.get(default_name)
            if entry and compatible(entry):
                return entry

        for entry in prompts.values():
            if compatible(entry):
                return entry

        return None

    def get_prompt(self, name: str | None = None, scan_mode: str = "pr-diff") -> str:
        """
        Load prompt content by name.

        Falls back to default_prompt if name is None.
        Falls back to built-in minimal prompt if manifest is empty.
        """
        entry = self._select_prompt_entry(name, scan_mode)
        if not entry:
            return self.builtin_minimal_prompt()

        file_name = entry.get("file")
        if not file_name:
            return self.builtin_minimal_prompt()

        prompt_path = self.prompts_dir / file_name
        if not prompt_path.exists():
            return self.builtin_minimal_prompt()

        return prompt_path.read_text(encoding="utf-8")

    def get_max_context_tokens(self, name: str | None = None) -> int:
        """Get max context tokens for a prompt."""
        prompts = self.manifest.get("prompts") or {}
        entry = None
        if name and name in prompts:
            entry = prompts.get(name)
        else:
            default_name = self.manifest.get("default_prompt")
            if default_name and default_name in prompts:
                entry = prompts.get(default_name)
        if not entry:
            return DEFAULT_MAX_CONTEXT_TOKENS
        max_tokens = entry.get("max_context_tokens")
        if isinstance(max_tokens, int) and max_tokens > 0:
            return max_tokens
        return DEFAULT_MAX_CONTEXT_TOKENS

    @staticmethod
    def builtin_minimal_prompt() -> str:
        """Fallback prompt when no manifest exists (dev/test mode)."""
        return (
            "You are a security code reviewer. Analyze the provided code for:\n"
            "1. Security vulnerabilities (injection, auth bypass, secrets exposure)\n"
            "2. Reliability issues (missing error handling, race conditions)\n"
            "3. Code quality problems\n\n"
            "Output findings as JSONL (one JSON object per line):\n"
            "{\"severity\": \"P0|P1|P2|P3\", \"category\": \"string\", \"file_path\": \"string\", "
            "\"line_start\": int, \"line_end\": int, \"message\": \"string\", "
            "\"recommendation\": \"string\", "
            "\"fix_plan\": \"1-3 sentence actionable pseudo-code\", "
            "\"confidence\": float}\n"
            "The fix_plan must be code-specific and concise (no fluff).\n\n"
            "If no issues found, output: {\"no_findings\": true}\n"
        )
