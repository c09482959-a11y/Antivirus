"""Public binary scanner contracts."""
from Virus_Scan.scanners.binary_failover import should_binary_failover
from Virus_Scan.scanners.binary_embedded_payloads import validated_embedded_payload_hits
from Virus_Scan.scanners.binary_pe import global_raw_pure_pe_header, scan_pure_python_pe_file
from Virus_Scan.scanners.binary_embedded_pickle import scan_binary_embedded_pickle_payloads

__all__ = (
    "global_raw_pure_pe_header",
    "scan_binary_embedded_pickle_payloads",
    "scan_pure_python_pe_file",
    "should_binary_failover",
    "validated_embedded_payload_hits",
)
