from __future__ import annotations

from pathlib import Path

from Virus_Scan.models.api.text_boundary import public_api_contract_text
from Virus_Scan.models.profiles.common import (
    PROFILE_TEXT_UNAVAILABLE,
    profile_iterable_items,
    profile_public_ordered_events,
    profile_public_tags,
    profile_public_yara_hits,
    profile_safe_text,
)
from Virus_Scan.models.profiles.corruption import profile_corruption_json_safe
from Virus_Scan.models.temporal.text_boundary import TEMPORAL_TEXT_UNAVAILABLE, temporal_boundary_text


_REPO_ROOT = Path(__file__).resolve().parents[2]
_TEXT_BOUNDARY_FILES = (
    Path("Virus_Scan/models/profiles/common.py"),
    Path("Virus_Scan/models/api/text_boundary.py"),
    Path("Virus_Scan/models/temporal/text_boundary.py"),
    Path("Virus_Scan/models/profiles/corruption.py"),
)


class HostileProfileText:
    touched = 0

    @property
    def text(self):  # pragma: no cover - failure proves descriptor probing returned
        type(self).touched += 1
        raise AssertionError("profile text property touched")


class HostileProfileValue:
    touched = 0

    @property
    def value(self):  # pragma: no cover - failure proves descriptor probing returned
        type(self).touched += 1
        raise AssertionError("profile value property touched")


class HostileProfileStr:
    touched = 0

    def __str__(self):  # pragma: no cover - failure proves caller hook executed
        type(self).touched += 1
        raise AssertionError("profile __str__ touched")

    def __repr__(self):  # pragma: no cover - failure proves caller hook executed
        type(self).touched += 1
        raise AssertionError("profile __repr__ touched")




class HostileProfileIterable:
    touched = 0

    def __iter__(self):  # pragma: no cover - failure proves iteration returned
        type(self).touched += 1
        raise AssertionError("profile iterable touched")

    def __len__(self):  # pragma: no cover - failure proves truthiness/len returned
        type(self).touched += 1
        raise AssertionError("profile len touched")

    def __repr__(self):  # pragma: no cover - failure proves repr returned
        type(self).touched += 1
        raise AssertionError("profile repr touched")


class HostileProfileMapping:
    touched = 0

    def __iter__(self):  # pragma: no cover - failure proves mapping iteration returned
        type(self).touched += 1
        raise AssertionError("profile mapping iter touched")

    def __len__(self):  # pragma: no cover - failure proves mapping len returned
        type(self).touched += 1
        raise AssertionError("profile mapping len touched")

    def __getitem__(self, key):  # pragma: no cover - failure proves mapping getitem returned
        type(self).touched += 1
        raise AssertionError("profile mapping getitem touched")


class PlainProfileText:
    def __init__(self, text: str) -> None:
        self.text = text


def _reset() -> None:
    HostileProfileText.touched = 0
    HostileProfileValue.touched = 0
    HostileProfileStr.touched = 0
    HostileProfileIterable.touched = 0
    HostileProfileMapping.touched = 0


def test_profile_safe_text_rejects_hostile_profile_text_value_and_str_hooks() -> None:
    _reset()

    assert profile_safe_text(HostileProfileText(), replacement="profile_unavailable") == "profile_unavailable"
    assert profile_safe_text(HostileProfileValue(), replacement="profile_unavailable") == "profile_unavailable"
    assert profile_safe_text(HostileProfileStr(), replacement="profile_unavailable") == "profile_unavailable"
    assert profile_safe_text(HostileProfileText()) == PROFILE_TEXT_UNAVAILABLE
    assert profile_safe_text(HostileProfileValue()) == PROFILE_TEXT_UNAVAILABLE
    assert profile_safe_text(HostileProfileStr()) == PROFILE_TEXT_UNAVAILABLE

    assert HostileProfileText.touched == 0
    assert HostileProfileValue.touched == 0
    assert HostileProfileStr.touched == 0


def test_profile_safe_text_accepts_plain_owned_instance_dict_text() -> None:
    assert profile_safe_text(PlainProfileText(" renpy ")) == "renpy"


def test_sibling_model_text_boundaries_reject_hostile_profile_hooks() -> None:
    _reset()

    public_text, public_reason = public_api_contract_text(HostileProfileText(), default_text="profile_unavailable")
    temporal_text = temporal_boundary_text(HostileProfileValue())
    corruption_safe = profile_corruption_json_safe(HostileProfileStr())

    assert (public_text, public_reason) == ("profile_unavailable", "unreadable_public_contract_text")
    assert temporal_text == TEMPORAL_TEXT_UNAVAILABLE
    assert corruption_safe["reason"] == "unsupported_profile_corruption_value"
    assert HostileProfileText.touched == 0
    assert HostileProfileValue.touched == 0
    assert HostileProfileStr.touched == 0


def test_model_text_boundaries_do_not_probe_profile_text_descriptors() -> None:
    offenders: list[str] = []
    forbidden_markers = (
        "getattr(value",
        "str(value",
        "repr(value",
        "format(value",
        ".__getattribute__(value",
        "fspath(value",
    )
    allowed_marker = 'object.__getattribute__(value, "__dict__")'
    for relative in _TEXT_BOUNDARY_FILES:
        source = (_REPO_ROOT / relative).read_text(encoding="utf-8")
        for lineno, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "``" in stripped:
                continue
            if allowed_marker in line:
                continue
            for marker in forbidden_markers:
                if marker in line:
                    offenders.append(f"{relative}:{lineno}:{marker}")

    assert offenders == []


def test_profile_public_collections_reject_unknown_iterables_and_mappings_without_hooks() -> None:
    _reset()

    assert profile_public_tags(HostileProfileIterable(), "malformed_profile_tags") == ((), "malformed_profile_tags")
    assert profile_public_yara_hits(HostileProfileIterable(), "malformed_profile_yara_hits") == ((), "malformed_profile_yara_hits")
    assert profile_iterable_items(HostileProfileIterable(), "malformed_profile_iterable") == ((), "malformed_profile_iterable")
    assert profile_public_ordered_events(HostileProfileIterable(), "malformed_ordered_profile_events") == ((), "malformed_ordered_profile_events")

    assert profile_public_tags(HostileProfileMapping(), "malformed_profile_tags") == ((), "malformed_profile_tags")
    assert profile_public_ordered_events(HostileProfileMapping(), "malformed_ordered_profile_events") == ((), "malformed_ordered_profile_events")

    assert HostileProfileIterable.touched == 0
    assert HostileProfileMapping.touched == 0
