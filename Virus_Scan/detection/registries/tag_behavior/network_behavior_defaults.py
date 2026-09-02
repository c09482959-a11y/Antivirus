"""Network tag-to-behavior defaults."""
from __future__ import annotations

from Virus_Scan.detection.registries.immutability import freeze_registry_value

NETWORK_TAG_TO_BEHAVIOR = freeze_registry_value({'backdoor_or_c2': 'backdoor_or_c2', 'blockchain_api_access': 'blockchain_activity', 'blockchain_c2_polling': 'backdoor_or_c2', 'blockchain_command_parse': 'backdoor_or_c2', 'blockchain_p2p_or_rpc': 'blockchain_activity', 'c2_beacon': 'backdoor_or_c2', 'c2_or_remote_command': 'backdoor_or_c2', 'exfiltration': 'network_exfiltration', 'http': 'url_present', 'http_upload': 'http_upload', 'miner_binary': 'cryptomining_behavior', 'mining_pool_connection': 'cryptomining_behavior', 'network_c2': 'backdoor_or_c2', 'network_download': 'network_download', 'network_exfiltration': 'network_exfiltration', 'remote_command_channel': 'backdoor_or_c2', 'remote_payload_download': 'network_download', 'reverse_shell': 'backdoor_or_c2', 'socket_usage': 'network_activity', 'stratum_protocol': 'cryptomining_behavior'})

__all__ = ("NETWORK_TAG_TO_BEHAVIOR",)
