from __future__ import annotations

import inspect

import Virus_Scan.publication.json_finalization.signal_projection as signal_projection


def test_stage1717_legacy_first_dict_helper_is_removed_from_public_surface() -> None:
    assert not hasattr(signal_projection, "first_dict")
    assert "first_dict" not in signal_projection.__all__

    source = inspect.getsource(signal_projection)
    assert "def first_dict" not in source
    assert "return {}" not in source[source.find("def signal_summary") : source.find("def contextual_signal_frame")]
