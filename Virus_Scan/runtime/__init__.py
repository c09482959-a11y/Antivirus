"""Runtime package namespace.

Package import is intentionally side-effect light.  Runtime objects must be
imported from their owned submodules so startup can import the runtime
orchestration boundary without constructing scanner, scheduler, reporting,
model, path, or mutable runtime state owners.
"""

__all__ = ()
