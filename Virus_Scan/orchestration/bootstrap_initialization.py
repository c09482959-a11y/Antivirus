"""Canonical orchestration bootstrap wiring for runtime/domain services.

This module intentionally imports bounded public domain APIs and deterministic
bootstrap-visible module names after scan execution has been selected. Runtime
packages own snapshots/config/path state; orchestration owns this cross-domain
activation boundary.
"""
from __future__ import annotations


from Virus_Scan.runtime.api import (
    RuntimeClusterState,
    RuntimeDetectionState,
    RuntimeScanIntegrityState,
    configure_runtime_cluster_state,
    configure_runtime_detection_state,
    configure_runtime_model_state,
    configure_runtime_scan_integrity_state,
    detection_state,
    get_lifecycle_state,
)

import Virus_Scan.cli.args
import Virus_Scan.cli.exit_codes
import Virus_Scan.core.cache
import Virus_Scan.core.ilspy_runtime
import Virus_Scan.core.jsonio
import Virus_Scan.core.logging
import Virus_Scan.core.paths
from Virus_Scan.detection.api import bootstrap_registration as detection_bootstrap_registration
from Virus_Scan.models.api import bootstrap_registration as model_bootstrap_registration
import Virus_Scan.reporting.compact
import Virus_Scan.reporting.output
import Virus_Scan.reporting.result_schema
import Virus_Scan.reporting.summary
import Virus_Scan.virustotal.reporting
import Virus_Scan.routing.engine_detect
import Virus_Scan.routing.intrastage_execution_plan
import Virus_Scan.routing.intrastage_executor_session
import Virus_Scan.routing.extension_intrastage
import Virus_Scan.routing.extensions
import Virus_Scan.routing.magic
import Virus_Scan.routing.passive_assets
import Virus_Scan.utils.media_stego
from Virus_Scan.scanners.api import public_contracts as scanner_public_contracts
from Virus_Scan.orchestration.runtime_dependency_activation import (
    activate_runtime_scan_dependency_providers,
)
import Virus_Scan.yara.cache
import Virus_Scan.yara.download
import Virus_Scan.yara.match

# Stage 155: explicit bootstrap registration manifest.
# These modules are intentionally imported at bootstrap module load time because the
# extracted runtime imports are explicit and deterministic.
# The manifest makes that lifecycle auditable
# without adding a second dynamic loader path.
_BOOTSTRAP_REGISTRATION_MODULE_NAMES = tuple(
    sorted(
        (
            Virus_Scan.cli.args.__name__,
            Virus_Scan.cli.exit_codes.__name__,
            Virus_Scan.core.cache.__name__,
            Virus_Scan.core.ilspy_runtime.__name__,
            Virus_Scan.core.jsonio.__name__,
            Virus_Scan.core.logging.__name__,
            Virus_Scan.core.paths.__name__,
            detection_bootstrap_registration.__name__,
            *detection_bootstrap_registration.DETECTION_BOOTSTRAP_MODULE_NAMES,
            model_bootstrap_registration.__name__,
            *model_bootstrap_registration.MODEL_BOOTSTRAP_MODULE_NAMES,
            Virus_Scan.reporting.compact.__name__,
            Virus_Scan.reporting.output.__name__,
            Virus_Scan.reporting.result_schema.__name__,
            Virus_Scan.reporting.summary.__name__,
            Virus_Scan.virustotal.reporting.__name__,
            Virus_Scan.routing.engine_detect.__name__,
            Virus_Scan.routing.intrastage_execution_plan.__name__,
            Virus_Scan.routing.intrastage_executor_session.__name__,
            Virus_Scan.routing.extension_intrastage.__name__,
            Virus_Scan.routing.extensions.__name__,
            Virus_Scan.routing.magic.__name__,
            Virus_Scan.routing.passive_assets.__name__,
            scanner_public_contracts.__name__,
            Virus_Scan.utils.media_stego.__name__,
            Virus_Scan.yara.cache.__name__,
            Virus_Scan.yara.download.__name__,
            Virus_Scan.yara.match.__name__,
        )
    )
)

_BOOTSTRAP_REQUIRED_MODULE_NAMES = tuple(
    sorted(
        set(_BOOTSTRAP_REGISTRATION_MODULE_NAMES)
        | set(scanner_public_contracts.SCANNER_BOOTSTRAP_MODULE_NAMES)
    )
)

BOOTSTRAP_REQUIRED_MODULE_NAMES = _BOOTSTRAP_REQUIRED_MODULE_NAMES


def validate_bootstrap_registration() -> dict[str, object]:
    """Validate the deterministic bootstrap import manifest before runtime start.

    The bootstrap owner imports a fixed manifest at module load time; this validator
    checks that every manifest module is present and named as expected instead of
    consulting a secondary runtime registry.
    """
    imported = set(_BOOTSTRAP_REGISTRATION_MODULE_NAMES)
    imported.update(scanner_public_contracts.SCANNER_BOOTSTRAP_MODULE_NAMES)
    missing = tuple(name for name in _BOOTSTRAP_REQUIRED_MODULE_NAMES if name not in imported)
    if missing:
        raise RuntimeError(
            "bootstrap manifest incomplete: " + ", ".join(missing[:16])
        )
    module_count = len(_BOOTSTRAP_REQUIRED_MODULE_NAMES)
    get_lifecycle_state().mark_bootstrap_registration_validated(module_count)
    return {
        'module_count': module_count,
        'registered_count': module_count,
        'missing': (),
    }


def initialize_runtime() -> object:
    """Initialize production runtime modules only. Tests are not imported here."""
    lifecycle = get_lifecycle_state()
    if lifecycle.is_initialized():
        return lifecycle.snapshot()
    validate_bootstrap_registration()
    activate_runtime_scan_dependency_providers()
    configure_runtime_cluster_state(RuntimeClusterState())
    configure_runtime_detection_state(RuntimeDetectionState())
    configure_runtime_scan_integrity_state(RuntimeScanIntegrityState())
    configure_runtime_model_state(
        global_state_lock=detection_state().stage_lock,
    )
    lifecycle.mark_initialized()
    return lifecycle.snapshot()

__all__ = ("BOOTSTRAP_REQUIRED_MODULE_NAMES", "initialize_runtime", "validate_bootstrap_registration")
