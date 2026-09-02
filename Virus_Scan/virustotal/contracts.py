"""Immutable VirusTotal configuration and reporting contracts."""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_materialize
from Virus_Scan.runtime.immutable_core import freeze_runtime_value

VIRUSTOTAL_REPORTING_STATUSES = frozenset({
    "unconfigured",
    "disabled",
    "configuration_invalid",
    "network_unavailable",
    "no_eligible_files",
    "quota_exhausted",
    "rate_limited",
    "submission_failed",
    "submitted_not_polled",
    "analysis_incomplete",
    "complete",
})


def _exact_text(value: object, reason: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value)
    if not allow_empty and text == "":
        raise ValueError(reason)
    return text


def _exact_count(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool or value < 0:
        raise ValueError(reason)
    return value


@dataclass(frozen=True, slots=True)
class VirusTotalReportingResult:
    """Final external-corroboration result without local-evidence authority."""

    status: str
    config_digest: str
    config_path: str
    api_key_environment_variable: str
    selected_count: int = 0
    submitted_count: int = 0
    skipped_count: int = 0
    results: tuple[object, ...] = ()
    errors: tuple[str, ...] = ()
    write_normalized_results: bool = True
    include_full_response: bool = False
    evidence_authority: str = "external_corroboration"
    local_result_mutated: bool = False

    def __post_init__(self) -> None:
        if type(self) is not VirusTotalReportingResult:
            raise TypeError("virustotal_reporting_result_owner_invalid")
        status = _exact_text(self.status, "virustotal_reporting_status_invalid")
        if status not in VIRUSTOTAL_REPORTING_STATUSES:
            raise ValueError("virustotal_reporting_status_invalid")
        digest = _exact_text(self.config_digest, "virustotal_config_digest_invalid", allow_empty=True)
        if digest != "" and (len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)):
            raise ValueError("virustotal_config_digest_invalid")
        config_path = _exact_text(self.config_path, "virustotal_config_path_invalid", allow_empty=True)
        env_name = _exact_text(
            self.api_key_environment_variable,
            "virustotal_api_key_environment_variable_invalid",
            allow_empty=status == "configuration_invalid",
        )
        if env_name == "" and status != "configuration_invalid":
            raise ValueError("virustotal_api_key_environment_variable_invalid")
        selected = _exact_count(self.selected_count, "virustotal_selected_count_invalid")
        submitted = _exact_count(self.submitted_count, "virustotal_submitted_count_invalid")
        skipped = _exact_count(self.skipped_count, "virustotal_skipped_count_invalid")
        if submitted + skipped > selected:
            raise ValueError("virustotal_result_counts_inconsistent")
        if type(self.results) is not tuple or type(self.errors) is not tuple:
            raise TypeError("virustotal_reporting_collections_invalid")
        error_values: list[str] = []
        for error in self.errors:
            error_values.append(_exact_text(error, "virustotal_reporting_error_invalid"))
        if type(self.write_normalized_results) is not bool:
            raise TypeError("virustotal_write_normalized_results_invalid")
        if type(self.include_full_response) is not bool:
            raise TypeError("virustotal_include_full_response_invalid")
        if self.evidence_authority != "external_corroboration":
            raise ValueError("virustotal_evidence_authority_invalid")
        if type(self.local_result_mutated) is not bool or self.local_result_mutated:
            raise ValueError("virustotal_local_result_mutation_forbidden")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "config_digest", digest)
        object.__setattr__(self, "config_path", config_path)
        object.__setattr__(self, "api_key_environment_variable", env_name)
        object.__setattr__(self, "selected_count", selected)
        object.__setattr__(self, "submitted_count", submitted)
        object.__setattr__(self, "skipped_count", skipped)
        object.__setattr__(self, "results", tuple(freeze_runtime_value(value) for value in self.results))
        object.__setattr__(self, "errors", tuple(error_values))

    def to_record(self) -> dict[str, object]:
        record = {
            "status": self.status,
            "config_digest": self.config_digest,
            "config_path": self.config_path,
            "api_key_environment_variable": self.api_key_environment_variable,
            "selected_count": self.selected_count,
            "submitted_count": self.submitted_count,
            "skipped_count": self.skipped_count,
            "results": self.results,
            "errors": self.errors,
            "write_normalized_results": self.write_normalized_results,
            "include_full_response": self.include_full_response,
            "evidence_authority": self.evidence_authority,
            "local_result_mutated": self.local_result_mutated,
        }
        materialized = no_hook_materialize(record)
        if type(materialized) is not dict:
            raise TypeError("virustotal_reporting_record_invalid")
        return materialized


__all__ = ("VIRUSTOTAL_REPORTING_STATUSES", "VirusTotalReportingResult")
