"""Deterministic inert-malicious execution oracle."""
from __future__ import annotations

import hashlib

from Virus_Scan.stress.corpus_policy import (
    INERT_MALICIOUS_EXPECTED_CLASSIFICATIONS,
    INERT_MALICIOUS_EXTENSIONS,
    INERT_MALICIOUS_FAMILIES,
    INERT_MALICIOUS_FORBIDDEN_TAGS,
    INERT_MALICIOUS_MAXIMUM_SCORE,
    INERT_MALICIOUS_MINIMUM_SCORE,
    INERT_MALICIOUS_ORACLE_SCHEMA_VERSION,
    INERT_MALICIOUS_REQUIRED_TAGS,
    INERT_MALICIOUS_STRESS_SAMPLES,
)
from Virus_Scan.stress.corpus_types import MaliciousCorpusManifest, MaliciousOracleCase

_TEMPLATE_ID = "static_indicator_v2"
_ORACLE_LEVEL = "bounded"
_EXPECTED_TERMINAL_STATUS = "completed_nonzero_exit"
_EXPECTED_PROFILE_LEARNING = "blocked_non_clean"


def inert_malicious_sample_bytes(sample_id: str, family: str, index: int) -> bytes:
    """Return inert evidence text that is never executed by the stress runner."""
    lines = (
        "UMIGE INERT MALICIOUS STRESS SAMPLE - NEVER EXECUTE",
        "STATIC INDICATOR VOCABULARY ONLY; NOT SCRIPT SYNTAX",
        "sample_id=" + sample_id,
        "family=" + family,
        "ordinal=" + int.__str__(index),
        "powershell indicator",
        "encodedcommand indicator",
        "invoke-webrequest indicator",
        "download indicator then exec indicator",
        "currentversion\\run persistence indicator",
        "runonce registry indicator",
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def malicious_oracle_case(index: int) -> MaliciousOracleCase:
    if type(index) is not int or index < 0 or index >= INERT_MALICIOUS_STRESS_SAMPLES:
        raise ValueError("malicious_oracle_index_rejected")
    slot = index % len(INERT_MALICIOUS_EXTENSIONS)
    family = INERT_MALICIOUS_FAMILIES[slot]
    extension = INERT_MALICIOUS_EXTENSIONS[slot]
    sample_id = "malicious_" + format(index, "05d")
    relative_path = "/".join(("scripts", family, sample_id + "__" + _TEMPLATE_ID + extension))
    payload = inert_malicious_sample_bytes(sample_id, family, index)
    return MaliciousOracleCase(
        index=index,
        sample_id=sample_id,
        family=family,
        template_id=_TEMPLATE_ID,
        extension=extension,
        relative_path=relative_path,
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        expected_classifications=INERT_MALICIOUS_EXPECTED_CLASSIFICATIONS,
        minimum_score=INERT_MALICIOUS_MINIMUM_SCORE,
        maximum_score=INERT_MALICIOUS_MAXIMUM_SCORE,
        required_tags=INERT_MALICIOUS_REQUIRED_TAGS,
        forbidden_tags=INERT_MALICIOUS_FORBIDDEN_TAGS,
        oracle_level=_ORACLE_LEVEL,
        expected_terminal_status=_EXPECTED_TERMINAL_STATUS,
        expected_profile_learning=_EXPECTED_PROFILE_LEARNING,
    )


def build_malicious_oracle_manifest(
    count: int = INERT_MALICIOUS_STRESS_SAMPLES,
    *,
    run_id: str = "stage2636-malicious",
) -> MaliciousCorpusManifest:
    if type(count) is not int or count < 1 or count > INERT_MALICIOUS_STRESS_SAMPLES:
        raise ValueError("malicious_oracle_count_rejected")
    if type(run_id) is not str or run_id.strip() == "":
        raise ValueError("malicious_oracle_run_id_rejected")
    cases = tuple(malicious_oracle_case(index) for index in range(count))
    return MaliciousCorpusManifest(
        schema_version=INERT_MALICIOUS_ORACLE_SCHEMA_VERSION,
        run_id=run_id,
        total_samples=count,
        cases=cases,
    )


__all__ = (
    "build_malicious_oracle_manifest",
    "inert_malicious_sample_bytes",
    "malicious_oracle_case",
)
