from __future__ import annotations

import Virus_Scan.models.clustering.api as clustering_api
import Virus_Scan.models.graph.api as graph_api
import Virus_Scan.models.markov.api as markov_api
import Virus_Scan.models.profiles.api as profile_api
import Virus_Scan.models.replay.api as replay_api
import Virus_Scan.models.temporal.api as temporal_api
import Virus_Scan.publication.model_evidence_projection as model_evidence_projection

_CANONICAL_PUBLIC_MODULES = (
    markov_api,
    temporal_api,
    profile_api,
    clustering_api,
    graph_api,
    replay_api,
    model_evidence_projection,
)


def test_stage1458_canonical_public_api_facades_do_not_expose_private_attributes() -> None:
    offenders: list[str] = []
    for module in _CANONICAL_PUBLIC_MODULES:
        for name in dir(module):
            if name.startswith("_") and not (name.startswith("__") and name.endswith("__")):
                offenders.append(f"{module.__name__}:{name}")
    assert offenders == []
