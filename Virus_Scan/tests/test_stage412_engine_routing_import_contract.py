import Virus_Scan.engine_routing as engine_routing


def test_engine_routing_clean_process_import_surface():
    module = engine_routing
    required = {
        "BaselineRouteRequest",
        "build_baseline_route",
        "classify_engine_context",
        "resolve_scan_engine_hint",
        "sniff_file_identity",
        "artifact_engine_from_identity",
    }
    assert required.issubset(set(module.__all__))


from Virus_Scan.engine_routing import BaselineRouteRequest, build_baseline_route


def test_engine_routing_baseline_route_is_canonical():

    route = build_baseline_route(
        BaselineRouteRequest(
            container_engine="renpy",
            artifact_engine="unity",
            declared_extension="dll",
            sniffed_type="pe",
            sniffed_embedded_types=("embedded_pe_signature",),
        )
    )
    assert route.contextual_baseline == "renpy::unity::.dll"
    assert route.extension_baseline == "unity/.dll"
    assert route.container_extension_baseline == "renpy/.dll"
    assert route.learning_allowed is False
