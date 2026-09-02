from __future__ import annotations

from Virus_Scan.publication.json_finalization.base_projection import bounded_signal_value
from Virus_Scan.publication.json_finalization.projection_text import safe_projection_text


class HostileProjectionProperty:
    text_touches = 0
    str_touches = 0
    repr_touches = 0

    @property
    def text(self) -> str:  # pragma: no cover - regression asserts no call
        HostileProjectionProperty.text_touches += 1
        raise RuntimeError("text property must not run")

    @property
    def _text(self) -> str:  # pragma: no cover - regression asserts no call
        HostileProjectionProperty.text_touches += 1
        raise RuntimeError("_text property must not run")

    @property
    def value(self) -> str:  # pragma: no cover - regression asserts no call
        HostileProjectionProperty.text_touches += 1
        raise RuntimeError("value property must not run")

    def __str__(self) -> str:  # pragma: no cover - regression asserts no call
        HostileProjectionProperty.str_touches += 1
        raise RuntimeError("str hook must not run")

    def __repr__(self) -> str:  # pragma: no cover - regression asserts no call
        HostileProjectionProperty.repr_touches += 1
        raise RuntimeError("repr hook must not run")


class PlainProjectionWrapper:
    def __init__(self, text: str) -> None:
        self._text = text

    def __str__(self) -> str:  # pragma: no cover - regression asserts no call
        raise RuntimeError("wrapper str hook must not run")


class PlainTextProjectionWrapper:
    def __init__(self, text: str) -> None:
        self.text = text

    def __str__(self) -> str:  # pragma: no cover - regression asserts no call
        raise RuntimeError("wrapper str hook must not run")


class PlainValueProjectionWrapper:
    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:  # pragma: no cover - regression asserts no call
        raise RuntimeError("wrapper str hook must not run")


def test_stage1560_final_json_projection_does_not_invoke_hostile_properties() -> None:
    HostileProjectionProperty.text_touches = 0
    HostileProjectionProperty.str_touches = 0
    HostileProjectionProperty.repr_touches = 0
    hostile = HostileProjectionProperty()

    text, reason = safe_projection_text(hostile)
    signal = bounded_signal_value(hostile)

    assert text == ""
    assert reason == "final_json_text_unavailable"
    assert signal["model_signal_projection_failed"] is True
    assert signal["reason"] == "final_json_text_unavailable"
    assert signal["value_type"] == "HostileProjectionProperty"
    assert HostileProjectionProperty.text_touches == 0
    assert HostileProjectionProperty.str_touches == 0
    assert HostileProjectionProperty.repr_touches == 0


def test_stage1560_final_json_projection_preserves_plain_instance_text_wrappers() -> None:
    assert safe_projection_text(PlainProjectionWrapper("legacy_text")) == ("legacy_text", "")
    assert safe_projection_text(PlainTextProjectionWrapper("public_text")) == ("public_text", "")
    assert safe_projection_text(PlainValueProjectionWrapper("value_text")) == ("value_text", "")
