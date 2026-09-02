"""No-hook scheduler exception text projection."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name

_SAFE_BUILTIN_EXCEPTION_TYPES = (OSError, RuntimeError, TypeError, ValueError, OverflowError)


def _scheduler_owned_exception_args_rejection(error: BaseException) -> str:
    error_type = type(error)
    try:
        module = type.__getattribute__(error_type, "__module__")
        mro = type.__getattribute__(error_type, "__mro__")
    except (AttributeError, TypeError, RuntimeError):
        return "scheduler_exception_type_metadata_rejected"
    if type(module) is not str or not module.startswith("Virus_Scan.scheduler."):
        return "scheduler_exception_not_owned"
    if type(mro) is not tuple:
        return "scheduler_exception_mro_rejected"
    for owner in mro:
        if owner is BaseException:
            break
        try:
            namespace = type.__getattribute__(owner, "__dict__")
        except (AttributeError, TypeError, RuntimeError):
            return "scheduler_exception_owner_namespace_rejected"
        if "args" in namespace:
            return "scheduler_exception_args_descriptor_rejected"
    return ""


def scheduler_error_detail(error: BaseException, *, max_length: int = 1000) -> str:
    type_name = no_hook_type_name(error)
    message = scheduler_exception_text(error, max_length=max_length)
    prefix = type_name + ":"
    if message.startswith(prefix):
        return message[:max(1, max_length)]
    return (prefix + " " + message)[:max(1, max_length)]


def scheduler_exception_text(
    error: BaseException,
    *,
    max_length: int = 1000,
    missing_text: str | None = None,
) -> str:
    """Return exception message text without invoking exception hooks."""
    type_name = no_hook_type_name(error)
    unavailable = (
        str.__str__(missing_text)
        if type(missing_text) is str
        else type_name + ": scheduler diagnostic detail unavailable without caller hooks"
    )
    if type(error) not in _SAFE_BUILTIN_EXCEPTION_TYPES:
        rejection = _scheduler_owned_exception_args_rejection(error)
        if rejection:
            return unavailable[:max(1, max_length)]
    try:
        args = BaseException.__getattribute__(error, "args")
    except (AttributeError, TypeError, RuntimeError):
        args = ()
    if type(args) is tuple:
        parts: list[str] = []
        for arg in args[:4]:
            text, reason = no_hook_text(arg, unsupported_reason="scheduler_error_arg_rejected")
            if reason == "" and text:
                parts.append(text)
        if parts:
            return "; ".join(parts)[:max(1, max_length)]
    return unavailable[:max(1, max_length)]


__all__ = ("scheduler_error_detail", "scheduler_exception_text")
