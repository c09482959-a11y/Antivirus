"""Credential tag-to-behavior defaults."""
from __future__ import annotations

from Virus_Scan.detection.registries.immutability import freeze_registry_value

CREDENTIAL_TAG_TO_BEHAVIOR = freeze_registry_value({'browser': 'credential_access',
 'browser_credential_access': 'browser_credential_access',
 'browser_extraction': 'credential_access',
 'browser_password_store_access': 'browser_credential_access',
 'browser_profile_access': 'credential_access',
 'browser_xhr_fetch': 'browser_xhr_fetch',
 'chrome_login_data_access': 'browser_credential_access',
 'comsvcs_exec': 'credential_dump_attempt',
 'credential_access': 'credential_access',
 'credential_access_attempt': 'credential_access',
 'credential_api_access': 'credential_access',
 'credential_dump_attempt': 'credential_dump_attempt',
 'credential_memory_access': 'credential_access',
 'crypto_wallet_clipboard_replace': 'collection',
 'crypto_wallet_pattern': 'collection',
 'dpapi_access': 'credential_access',
 'dpapi_credential_access': 'dpapi_access',
 'firefox_login_data_access': 'browser_credential_access',
 'lsass_access': 'lsass_access',
 'memory_dump': 'credential_access',
 'password': 'credential_access',
 'token_exfiltration': 'network_exfiltration',
 'token_secret_access': 'credential_access'})

__all__ = ("CREDENTIAL_TAG_TO_BEHAVIOR",)
