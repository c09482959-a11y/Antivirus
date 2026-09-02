from Virus_Scan.runtime.provenance import _stable_jsonish, stable_digest


def test_provenance_set_values_are_canonicalized_in_sorted_order():
    event = {"evidence": {"beta", "alpha", "gamma"}}

    canonical = _stable_jsonish(event)

    assert canonical == {"evidence": ["alpha", "beta", "gamma"]}


def test_provenance_stable_digest_does_not_depend_on_set_insertion_source():
    left = {"evidence": set(["gamma", "alpha", "beta"])}
    right = {"evidence": frozenset(["beta", "gamma", "alpha"])}

    assert stable_digest(left) == stable_digest(right)
