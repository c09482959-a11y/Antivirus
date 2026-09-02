"""Immutable request contracts for profile-model mutation and validation owners."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProfileBucketValidationRequest:
    engine: object
    file_path: object
    tags: object
    strings_blob: object = ""
    api_calls: object = None
    ordered_events: object = None


@dataclass(frozen=True, slots=True)
class ProfileLearningGateRequest:
    engine: object
    file_path: object
    tags: object
    risk: object = 0.0
    strings_blob: object = ""
    verdict: object = None
    api_calls: object = None
    ordered_events: object = None
    scan_integrity: object = None


@dataclass(frozen=True, slots=True)
class ExtensionBaselineUpdateRequest:
    engine: object
    file_path: object
    tags: object
    yara_hits: object = None
    risk: object = 0.0
    strings_blob: object = ""
    verdict: object = None
    api_calls: object = None
    ordered_events: object = None
    learning_allowed: object = None


__all__ = ("ExtensionBaselineUpdateRequest", "ProfileBucketValidationRequest", "ProfileLearningGateRequest")
