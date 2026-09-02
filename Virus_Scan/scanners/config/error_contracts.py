"""Visible scanner configuration failure contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_owner_field, no_hook_type_name
from Virus_Scan.scanners.contracts.scanner_evidence import freeze_scanner_evidence_records
from Virus_Scan.scanners.config.immutable_policy import policy_text


@dataclass(frozen=True, slots=True)
class ScannerConfigFailure:
    config_name: str
    source: str
    reason: str
    failure_evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "config_name", policy_text(self.config_name, default="scanner_config"))
        object.__setattr__(self, "source", policy_text(self.source))
        object.__setattr__(self, "reason", policy_text(self.reason))
        object.__setattr__(self, "failure_evidence", freeze_scanner_evidence_records(self.failure_evidence))


class ScannerConfigError(ValueError):
    """Visible scanner configuration validation failure."""

    def __init__(self, failure: ScannerConfigFailure) -> None:
        if type(failure) is ScannerConfigFailure:
            config_name = no_hook_exact_owner_field(failure, ScannerConfigFailure, "config_name")
            reason = no_hook_exact_owner_field(failure, ScannerConfigFailure, "reason")
        else:
            config_name = "scanner_config"
            reason = str.__add__("unsupported_failure_type:", no_hook_type_name(failure))
        super().__init__(str.__add__(str.__add__(policy_text(config_name, default="scanner_config"), " invalid: "), policy_text(reason)))
        self.failure = failure


__all__ = ("ScannerConfigError", "ScannerConfigFailure")
