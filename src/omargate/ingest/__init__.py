"""Codebase ingest pipeline utilities."""

from .file_classifier import FileClassification, classify_file
from .hotspot_detector import (
    HOTSPOT_PATTERNS,
    build_hotspot_map,
    hotspot_categories_for_path,
)
from .ingest_runner import run_ingest
from .quick_learn import (
    QuickLearnSummary,
    build_llm_synopsis_prompt,
    extract_quick_learn_summary,
    is_boilerplate_description,
)

__all__ = [
    "HOTSPOT_PATTERNS",
    "FileClassification",
    "QuickLearnSummary",
    "build_hotspot_map",
    "build_llm_synopsis_prompt",
    "classify_file",
    "extract_quick_learn_summary",
    "hotspot_categories_for_path",
    "is_boilerplate_description",
    "run_ingest",
]
