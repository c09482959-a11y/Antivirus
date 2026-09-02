# Real module split from v27c for models/learning.py.
# Functionality lives here; shared state is synchronized through this subsystem state module.
import threading

# Stage 27 explicit bootstrap-safe dependencies; scanners no longer rely on
# init_runtime injecting these callables into module globals.

_LEARNING_REENTRY_STATE = threading.local()


def _learning_state() -> object:
    return vars(_LEARNING_REENTRY_STATE)


def _learning_in_progress() -> object:
    return dict.get(_learning_state(), "active") is True


class learning_guard:
    def __enter__(self) -> object:
        if _learning_in_progress():
            return False
        _LEARNING_REENTRY_STATE.active = True
        return True

    def __exit__(self, exc_type: object, exc: object, tb: object) -> object:
        _LEARNING_REENTRY_STATE.active = False
        return False




