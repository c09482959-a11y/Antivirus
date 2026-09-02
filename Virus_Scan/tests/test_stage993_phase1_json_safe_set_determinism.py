
from Virus_Scan.contracts.worker_record import make_json_safe as worker_make_json_safe
from Virus_Scan.core.jsonio import make_json_safe as core_make_json_safe
from Virus_Scan.scheduler.runtime.queue_json_safety import make_json_safe as queue_make_json_safe


def test_json_safe_set_converters_accept_mixed_scalar_sets():
    expected = [1, "2"]

    assert core_make_json_safe({"items": {"2", 1}})["items"] == expected
    assert queue_make_json_safe({"items": {"2", 1}})["items"] == expected
    assert worker_make_json_safe({"items": {"2", 1}})["items"] == expected


def test_json_safe_set_converters_handle_frozenset_without_stringifying_container():
    expected = ["alpha", "beta"]

    assert core_make_json_safe({"items": frozenset({"beta", "alpha"})})["items"] == expected
    assert queue_make_json_safe({"items": frozenset({"beta", "alpha"})})["items"] == expected
    assert worker_make_json_safe({"items": frozenset({"beta", "alpha"})})["items"] == expected


def test_queue_json_safe_set_order_is_stable_across_hash_seeds():
    first = queue_make_json_safe({"items": {"b", "a", 1}})["items"]
    second = queue_make_json_safe({"items": set(reversed(("a", "b", 1)))})["items"]
    third = queue_make_json_safe({"items": frozenset({"b", "a", 1})})["items"]

    assert first == [1, "a", "b"]
    assert second == first
    assert third == first


def test_json_safe_set_sources_do_not_use_raw_sorted_generator_for_sets():
    for func in (core_make_json_safe, queue_make_json_safe, worker_make_json_safe):
        source = func.__globals__.get("__file__")
        assert source
        text = open(source, encoding="utf-8").read()
        assert "sorted(make_json_safe(item, _key) for item in value)" not in text
        assert "sorted((make_json_safe(v, _key) for v in value))" not in text
