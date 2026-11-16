"""Local-only correlation of normalized Windows events and existing IOC results."""

from .engine import CorrelationConfig, correlate
from .models import InvestigationCase

__all__ = ["CorrelationConfig", "InvestigationCase", "correlate"]
