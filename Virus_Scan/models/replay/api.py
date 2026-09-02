"""Public replay model API."""
from __future__ import annotations


from Virus_Scan.models.replay import detachment as replay_detachment_owner
from Virus_Scan.models.replay import learning as replay_learning_owner
from Virus_Scan.models.replay import payload as replay_payload_owner


def detach_replay_payload_mapping(value: object) -> object:
    """Detach replay mappings through the canonical replay owner."""
    return replay_detachment_owner.detach_replay_payload_mapping(value)


def detach_replay_payload_value(value: object) -> object:
    """Detach one replay payload value through the canonical replay owner."""
    return replay_detachment_owner.detach_replay_payload_value(value)


def parent_replay_result_learning(result: object) -> dict[str, object]:
    """Process one parent replay result through canonical replay learning."""
    return replay_learning_owner.parent_replay_result_learning(result)


def persist_parent_learning_from_results(results: object) -> dict[str, object]:
    """Persist replay learning through the canonical replay implementation."""
    return replay_learning_owner.persist_parent_learning_from_results(results)



def result_learning_payload(result: object) -> dict[str, object] | None:
    """Build parent replay learning payload through the canonical replay owner."""
    return replay_payload_owner.result_learning_payload(result)


__all__ = (
    "detach_replay_payload_mapping",
    "detach_replay_payload_value",
    "parent_replay_result_learning",
    "persist_parent_learning_from_results",
    "result_learning_payload",
)
