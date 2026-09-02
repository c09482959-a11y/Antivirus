UMIGE canonical scan publication root

Each scan receives one generated identity and writes only inside:

  Scan Logs/.staging/<scan_id>/

The current staging generation owns scan_results.json, scanlog, and virustotal_results.json together with later subsystem summaries. Completed immutable generations will be activated under Scan Logs/runs/<scan_id>/ through the canonical report-set publisher. Scan Logs/latest.json is reserved for atomic activation and is not written until a complete manifested generation exists.

Do not place scan targets, secrets, caches, or mutable model state in this root.
