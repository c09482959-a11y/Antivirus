"""Canonical scanner API namespace.

Import bounded public-contract modules directly; this package initializer avoids
loading all scanner domains eagerly so scanner submodules cannot create public
API cycles during their own imports.
"""

__all__ = ()
