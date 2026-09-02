"""Narrow public API for publication-owned side effects."""

from __future__ import annotations

from Virus_Scan.publication.json_writer import (
    finalize_scan_results,
    recover_results_from_partial,
    write_partial_scan_results,
)
from Virus_Scan.publication.report_set import (
    ReportManifest,
    ReportSetPublicationResult,
    ScanPublicationSnapshot,
    build_scan_publication_snapshot,
    publish_scan_report_set,
    verify_report_manifest,
)
from Virus_Scan.publication.yara_summary import (
    YaraFindingSummaryRow,
    YaraFindingsSummary,
    YaraScanSummaryRow,
    build_yara_findings_summary,
    render_yara_findings_summary,
)
from Virus_Scan.publication.chain_summary import (
    ChainEvidenceSummaryRow,
    ChainFindingSummaryRow,
    ChainFindingsSummary,
    build_chain_findings_summary,
    render_chain_findings_summary,
)
from Virus_Scan.publication.cluster_summary import (
    ClusterCandidateSummaryRow,
    ClusterEvidenceSummaryRow,
    ClusterFindingsSummary,
    build_cluster_findings_summary,
    render_cluster_findings_summary,
)
from Virus_Scan.publication.scan_result_ledger import (
    ScanResultLedgerAccumulator,
    emit_scan_result_ledger,
)

from Virus_Scan.publication.api.pipeline_finalization import (
    clear_profile_scoring_snapshot,
    flush_all_persistent_models,
    persist_parent_learning_from_results,
)
from Virus_Scan.publication.api.retained_result import build_retained_publication_record

__all__ = (
    "render_cluster_findings_summary",
    "build_cluster_findings_summary",
    "ClusterFindingsSummary",
    "ClusterEvidenceSummaryRow",
    "ClusterCandidateSummaryRow",
    "render_chain_findings_summary",
    "build_chain_findings_summary",
    "ChainFindingsSummary",
    "ChainFindingSummaryRow",
    "ChainEvidenceSummaryRow",
    "render_yara_findings_summary",
    "build_yara_findings_summary",
    "YaraScanSummaryRow",
    "YaraFindingsSummary",
    "YaraFindingSummaryRow",
    "verify_report_manifest",
    "publish_scan_report_set",
    "build_scan_publication_snapshot",
    "ScanPublicationSnapshot",
    "ReportSetPublicationResult",
    "ReportManifest",
    "build_retained_publication_record",
    "clear_profile_scoring_snapshot",
    "finalize_scan_results",
    "emit_scan_result_ledger",
    "ScanResultLedgerAccumulator",
    "flush_all_persistent_models",
    "persist_parent_learning_from_results",
    "recover_results_from_partial",
    "write_partial_scan_results",
)
