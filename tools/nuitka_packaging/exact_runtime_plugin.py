"""Nuitka lifecycle hook for exact immutable packaged runtime finalization."""
from __future__ import annotations

from pathlib import Path

from nuitka.plugins.PluginBase import NuitkaPluginBase

from tools.nuitka_packaging.exact_runtime_finalizer import (
    finalize_exact_packaged_runtimes,
)
from tools.nuitka_packaging.package_resource_projection import (
    canonical_package_resource_records,
    verify_standalone_package_resources,
)


class Stage263611020ExactRuntimePlugin(NuitkaPluginBase):
    """Project package resources and finalize exact standalone runtime bytes."""

    plugin_name = __name__

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._package_resources_emitted = False

    def considerDataFiles(self, module: object):
        if self._package_resources_emitted:
            return
        get_full_name = getattr(module, "getFullName", None)
        if get_full_name is None or str(get_full_name()) != "Virus_Scan.runtime.resource_paths":
            return
        repository_root = Path(__file__).resolve().parents[2]
        for record in canonical_package_resource_records(repository_root):
            yield self.makeIncludedDataFile(
                source_path=record.source_path,
                dest_path=record.relative_path,
                reason="canonical immutable resource-root package projection",
                tags="config",
            )
        self._package_resources_emitted = True

    def onStandaloneDistributionFinished(self, dist_dir: str) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        distribution_root = Path(dist_dir)
        finalize_exact_packaged_runtimes(repository_root, distribution_root)
        verify_standalone_package_resources(repository_root, distribution_root)
