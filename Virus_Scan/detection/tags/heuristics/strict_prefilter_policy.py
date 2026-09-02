"""Detection-owned strict prefilter token policy.

The strict fast prefilter uses this immutable token-to-tag mapping during raw
artifact triage. Keeping the mapping under detection/orchestration removes detection
policy ownership from scheduler initialization while preserving the existing
heuristic behavior.
"""

from types import MappingProxyType

STRICT_FAST_PREFILTER_TAG_MAP = MappingProxyType({
    'powershell': ('powershell_exec', 'process_exec'),
    'pwsh': ('powershell_exec', 'process_exec'),
    '-enc': ('encoded_powershell', 'powershell_exec'),
    'encodedcommand': ('encoded_powershell', 'powershell_exec'),
    'cmd.exe': ('cmd_exec', 'process_exec'),
    '/c ': ('cmd_exec', 'process_exec'),
    'wscript': ('script_host_exec', 'lolbin_execution', 'process_exec'),
    'cscript': ('script_host_exec', 'lolbin_execution', 'process_exec'),
    'mshta': ('mshta_exec', 'lolbin_execution', 'process_exec'),
    'rundll32': ('rundll32_exec', 'lolbin_execution', 'process_exec'),
    'wmic': ('wmic_exec', 'lolbin_execution', 'process_exec'),
    'reg add': ('registry_write', 'registry_persistence'),
    'currentversion\\run': ('registry_persistence',),
    'schtasks': ('scheduled_task', 'persistence'),
    'certutil': ('certutil_download', 'network_download', 'lolbin_execution'),
    'bitsadmin': ('bitsadmin_download', 'network_download', 'lolbin_execution'),
    'curl ': ('network_download',),
    'wget ': ('network_download',),
    'invoke-webrequest': ('network_download', 'powershell_exec'),
    'downloadstring': ('network_download', 'powershell_exec'),
    'http://': ('url_present', 'network_activity'),
    'https://': ('url_present', 'network_activity'),
    'ftp://': ('url_present', 'network_activity'),
    'frombase64string': ('encoded_powershell', 'base64_decode'),
    'base64': ('base64_decode', 'encoded_content'),
    'subprocess': ('process_exec',),
    'os.system': ('process_exec',),
    'eval(': ('dynamic_code_exec',),
    'exec(': ('dynamic_code_exec',),
    'pickle.loads': ('unsafe_deserialization', 'dynamic_code_exec'),
    'marshal.loads': ('unsafe_deserialization', 'dynamic_code_exec'),
    'virtualalloc': ('memory_alloc',),
    'virtualallocex': ('memory_alloc',),
    'writeprocessmemory': ('memory_write',),
    'createremotethread': ('thread_execution',),
    'ntcreatethreadex': ('thread_execution',),
    'queueuserapc': ('thread_execution',),
    'setthreadcontext': ('thread_execution',),
    'amsi': ('amsi_bypass_attempt', 'defense_evasion'),
    'etw': ('etw_bypass_attempt', 'defense_evasion'),
    'defender': ('defender_disable', 'defense_evasion'),
    'vssadmin': ('shadowcopy_delete', 'defense_evasion'),
    'shadowcopy': ('shadowcopy_delete', 'defense_evasion'),
})
