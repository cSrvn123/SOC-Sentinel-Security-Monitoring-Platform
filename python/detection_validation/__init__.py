"""Models for local, synthetic detection validation.

This package keeps structural inspection and Python-expression approximation
separate from genuine Wazuh rule-engine validation.
"""

from .models import (
    ApproximationCaseStatus,
    ApproximationObservation,
    CaseCategory,
    ExpectedMatchStatus,
    ExpectedOutcome,
    ObservedApproximationOutcome,
    PerCaseValidationResult,
    RuleMetadata,
    StructuralStatus,
    StructuralValidationResult,
    ValidationCase,
    ValidationReport,
    WazuhEngineStatus,
)
from .loader import validate_detection_001_xml
from .runner import ManifestValidationError, load_manifest, run_manifest_approximation
from .formatting import format_json, format_markdown

__all__ = [
    "ApproximationCaseStatus",
    "ApproximationObservation",
    "CaseCategory",
    "ExpectedMatchStatus",
    "ExpectedOutcome",
    "ObservedApproximationOutcome",
    "PerCaseValidationResult",
    "RuleMetadata",
    "StructuralStatus",
    "StructuralValidationResult",
    "ValidationCase",
    "ValidationReport",
    "WazuhEngineStatus",
    "validate_detection_001_xml",
    "ManifestValidationError",
    "load_manifest",
    "run_manifest_approximation",
    "format_json",
    "format_markdown",
]
