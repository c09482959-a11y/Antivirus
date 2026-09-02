"""Canonical startup eligibility lifecycle for VirusTotal external corroboration."""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path

from Virus_Scan.runtime.resource_paths import ResourceRootSnapshot
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.virustotal.client import VirusTotalClient
from Virus_Scan.virustotal.config import VirusTotalConfig, load_config
from Virus_Scan.virustotal.control_files import ensure_generated_controls

VIRUSTOTAL_RUNTIME_STATUSES = frozenset({
    "configuration_invalid",
    "disabled",
    "network_unavailable",
    "unconfigured",
    "enabled",
})


@dataclass(frozen=True, slots=True)
class VirusTotalRuntimeSnapshot:
    """Immutable session-scoped VirusTotal activation state.

    The client may hold the API key in memory only for an enabled session.  Secret
    material is intentionally excluded from repr, equality projections, digests,
    logs, and publication records.
    """

    status: str
    config_path: str
    config: VirusTotalConfig | None
    network_checked: bool
    credentials_checked: bool
    client: VirusTotalClient | None = field(default=None, repr=False, compare=False)
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self) is not VirusTotalRuntimeSnapshot:
            raise TypeError("virustotal_runtime_snapshot_owner_invalid")
        if type(self.status) is not str or self.status not in VIRUSTOTAL_RUNTIME_STATUSES:
            raise ValueError("virustotal_runtime_status_invalid")
        if type(self.config_path) is not str or self.config_path == "":
            raise ValueError("virustotal_runtime_config_path_invalid")
        if self.config is not None and type(self.config) is not VirusTotalConfig:
            raise TypeError("virustotal_runtime_config_invalid")
        if type(self.network_checked) is not bool or type(self.credentials_checked) is not bool:
            raise TypeError("virustotal_runtime_check_state_invalid")
        if type(self.errors) is not tuple or any(type(item) is not str or item == "" for item in self.errors):
            raise TypeError("virustotal_runtime_errors_invalid")
        if self.status == "configuration_invalid":
            if self.config is not None or self.network_checked or self.credentials_checked or self.client is not None:
                raise ValueError("virustotal_runtime_state_inconsistent")
        elif self.status == "disabled":
            if self.config is None or self.config.enabled or self.network_checked or self.credentials_checked or self.client is not None:
                raise ValueError("virustotal_runtime_state_inconsistent")
        elif self.status == "network_unavailable":
            if self.config is None or not self.config.enabled or not self.network_checked or self.credentials_checked or self.client is not None:
                raise ValueError("virustotal_runtime_state_inconsistent")
        elif self.status == "unconfigured":
            if self.config is None or not self.config.enabled or not self.network_checked or not self.credentials_checked or self.client is not None:
                raise ValueError("virustotal_runtime_state_inconsistent")
        elif self.status == "enabled":
            if self.config is None or not self.config.enabled or not self.network_checked or not self.credentials_checked:
                raise ValueError("virustotal_runtime_state_inconsistent")
            if type(self.client) is not VirusTotalClient or self.client.config != self.config:
                raise ValueError("virustotal_runtime_client_invalid")

    @property
    def config_digest(self) -> str:
        return "" if self.config is None else self.config.semantic_digest()

    @property
    def api_key_environment_variable(self) -> str:
        return "" if self.config is None else self.config.api_key_environment_variable


def _snapshot(
    status: str,
    config_path: Path,
    config: VirusTotalConfig | None,
    *,
    network_checked: bool,
    credentials_checked: bool,
    client: VirusTotalClient | None = None,
    errors: tuple[str, ...] = (),
) -> VirusTotalRuntimeSnapshot:
    return VirusTotalRuntimeSnapshot(
        status=status,
        config_path=config_path.as_posix(),
        config=config,
        network_checked=network_checked,
        credentials_checked=credentials_checked,
        client=client,
        errors=errors,
    )


def initialize_virustotal_runtime(roots: ResourceRootSnapshot) -> VirusTotalRuntimeSnapshot:
    """Ensure controls and freeze VirusTotal eligibility in the required order."""
    if type(roots) is not ResourceRootSnapshot:
        raise TypeError("virustotal_resource_root_snapshot_invalid")
    root = Path(roots.virustotal_root)
    controls = ensure_generated_controls(root)
    config_path = controls["config"]
    try:
        config = load_config(config_path)
    except (OSError, TypeError, ValueError) as exc:
        record_suppressed_failure("virustotal_configuration_invalid", exc, domain="configuration")
        return _snapshot(
            "configuration_invalid",
            config_path,
            None,
            network_checked=False,
            credentials_checked=False,
            errors=(type(exc).__name__,),
        )
    if not config.enabled:
        return _snapshot(
            "disabled",
            config_path,
            config,
            network_checked=False,
            credentials_checked=False,
        )
    if not VirusTotalClient.probe_connectivity(config.network_check_timeout_sec):
        return _snapshot(
            "network_unavailable",
            config_path,
            config,
            network_checked=True,
            credentials_checked=False,
        )
    api_key = os.environ.get(config.api_key_environment_variable, "")
    if type(api_key) is not str or api_key == "":
        return _snapshot(
            "unconfigured",
            config_path,
            config,
            network_checked=True,
            credentials_checked=True,
        )
    client = VirusTotalClient(config=config, api_key=api_key)
    return _snapshot(
        "enabled",
        config_path,
        config,
        network_checked=True,
        credentials_checked=True,
        client=client,
    )


__all__ = (
    "VIRUSTOTAL_RUNTIME_STATUSES",
    "VirusTotalRuntimeSnapshot",
    "initialize_virustotal_runtime",
)
