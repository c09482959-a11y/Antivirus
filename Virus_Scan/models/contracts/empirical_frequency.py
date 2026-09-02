"""Immutable bounded empirical-frequency estimator contract."""
from __future__ import annotations

from types import MappingProxyType
from typing import Final

EMPIRICAL_FREQUENCY_ESTIMATOR: Final[str] = "laplace_beta_binomial_v1"
EMPIRICAL_FREQUENCY_ALPHA: Final[float] = 1.0
EMPIRICAL_FREQUENCY_BETA: Final[float] = 1.0


def unavailable_empirical_frequency_record(reason: str, *, support: int = 0, successes: int = 0,
                        minimum_support: int = 1, maturity: str = "unknown",
                        suppression_authority: float = 0.0) -> object:
    return MappingProxyType({
        "probability": 0.0,
        "ready": False,
        "reason": reason,
        "successes": successes,
        "support": support,
        "minimum_support": minimum_support,
        "maturity": maturity,
        "suppression_authority": suppression_authority,
        "estimator": EMPIRICAL_FREQUENCY_ESTIMATOR,
        "prior": MappingProxyType({
            "family": "beta",
            "alpha": EMPIRICAL_FREQUENCY_ALPHA,
            "beta": EMPIRICAL_FREQUENCY_BETA,
            "source": "fixed_smoothing_prior_not_learned",
        }),
    })


def empirical_frequency_record(
    successes: object,
    support: object,
    *,
    minimum_support: object,
    maturity: object,
    suppression_authority: object,
) -> object:
    """Return one immutable smoothed empirical-frequency evidence record."""
    if type(minimum_support) is not int or type(minimum_support) is bool or minimum_support < 1:
        return unavailable_empirical_frequency_record("invalid_empirical_minimum_support")
    if type(support) is not int or type(support) is bool or support < 0:
        return unavailable_empirical_frequency_record(
            "invalid_empirical_support", minimum_support=minimum_support,
        )
    if type(successes) is not int or type(successes) is bool or successes < 0:
        return unavailable_empirical_frequency_record(
            "invalid_empirical_successes", support=support,
            minimum_support=minimum_support,
        )
    if successes > support:
        return unavailable_empirical_frequency_record(
            "empirical_successes_exceed_support", support=support,
            successes=successes, minimum_support=minimum_support,
        )
    maturity_text = maturity if type(maturity) is str and maturity else "unknown"
    authority = (
        suppression_authority
        if type(suppression_authority) is float
        and 0.0 <= suppression_authority <= 1.0
        else 0.0
    )
    if support < minimum_support:
        return unavailable_empirical_frequency_record(
            "insufficient_trusted_profile_support",
            support=support,
            successes=successes,
            minimum_support=minimum_support,
            maturity=maturity_text,
            suppression_authority=authority,
        )
    probability = (
        successes + EMPIRICAL_FREQUENCY_ALPHA
    ) / (
        support + EMPIRICAL_FREQUENCY_ALPHA + EMPIRICAL_FREQUENCY_BETA
    )
    return MappingProxyType({
        "probability": probability,
        "ready": True,
        "reason": None,
        "successes": successes,
        "support": support,
        "minimum_support": minimum_support,
        "maturity": maturity_text,
        "suppression_authority": authority,
        "estimator": EMPIRICAL_FREQUENCY_ESTIMATOR,
        "prior": MappingProxyType({
            "family": "beta",
            "alpha": EMPIRICAL_FREQUENCY_ALPHA,
            "beta": EMPIRICAL_FREQUENCY_BETA,
            "source": "fixed_smoothing_prior_not_learned",
        }),
    })


__all__ = (
    "EMPIRICAL_FREQUENCY_ALPHA",
    "EMPIRICAL_FREQUENCY_BETA",
    "EMPIRICAL_FREQUENCY_ESTIMATOR",
    "empirical_frequency_record",
    "unavailable_empirical_frequency_record",
)
