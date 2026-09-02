"""Public entropy scanner contracts."""
from Virus_Scan.scanners.entropy import _strict_fast_entropy as strict_fast_entropy, byte_entropy, detect_packer_entropy_anomaly, entropy_bytes, tag_entropy
__all__ = ("byte_entropy", "detect_packer_entropy_anomaly", "entropy_bytes", "strict_fast_entropy", "tag_entropy")
