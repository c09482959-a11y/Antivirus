"""Startup-only decision package for UMIGE."""
from __future__ import annotations

from Virus_Scan.startup.decision import RuntimeRequest, StartupDecision, StartupDecisionKind
from Virus_Scan.startup.cli_entry import evaluate

__all__ = ("RuntimeRequest", "StartupDecision", "StartupDecisionKind", "evaluate")
