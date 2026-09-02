"""Canonical contextual persistence and credential-access rule ownership."""

from Virus_Scan.detection.contracts.string_predicates import context_any, context_regex


def _append_service_and_account_persistence_tags(blob: object, tags: list[str]) -> None:
    if context_any(blob, ['createservice', 'createservicea', 'createservicew', 'new-service', 'sc.exe create', 'sc create']):
        tags.extend(['service_create', 'service_persistence', 'persistence'])
        if context_any(blob, ['localsystem', 'service_auto_start', 'auto_start', 'startservice', 'changeserviceconfig', 'service_all_access']):
            tags.append('service_persistence')
    if context_regex('\\b(?:net(?:\\.exe)?\\s+user|new-localuser)\\b', blob) and context_regex('\\b(?:/add|-password|password|active:yes)\\b', blob):
        tags.extend(['admin_user_creation', 'privileged_group_mod', 'persistence'])
    if (
        context_any(blob, ['net localgroup administrators', 'net.exe localgroup administrators', 'add-localgroupmember', 'groupadd sudo'])
        and context_any(blob, ['/add', '-member', '-group', 'usermod'])
    ) or context_regex(r'usermod\s+-a[gG]\s+sudo', blob):
        tags.extend(['local_admin_add', 'privileged_group_mod', 'persistence'])


def _append_scheduled_and_registry_persistence_tags(blob: object, tags: list[str]) -> None:
    if context_regex('\\bschtasks(?:\\.exe)?\\b', blob) and context_regex('/(?:create|run|change|delete|sc|tn|tr)\\b', blob):
        tags.append('schtasks_create')
        if context_regex('/s\\s+[^\\s]+|\\\\\\\\|admin\\$|psexec|wmic', blob):
            tags.append('remote_scheduled_task')
    if context_regex('\\bat(?:\\.exe)?\\b\\s+\\d{1,2}:\\d{2}\\b', blob):
        tags.append('at_exec')
    if context_regex('\\bcrontab\\b', blob) and context_regex('(?:^|\\s)-(?:e|l|r)\\b|/etc/cron', blob):
        tags.append('cron_modify')
    if context_regex('\\bsystemctl\\b', blob) and context_regex('\\b(?:enable|start|restart|daemon-reload)\\b', blob):
        tags.append('systemd_modify')
    if context_regex('(?:currentversion\\\\run(?:once)?|\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run|start menu\\\\programs\\\\startup|appinit_dlls|winlogon)', blob):
        tags.extend(['run_key_mod', 'registry_mod', 'registry_persistence', 'startup_persistence', 'persistence'])


def _append_credential_access_tags(blob: object, tags: list[str]) -> None:
    if context_any(blob, ['mimikatz', 'sekurlsa', 'sekurlsa::logonpasswords', 'lsadump', 'minidumpwritedump', 'nanodump']):
        tags.extend(['credential_dump_attempt', 'credential_access', 'memory_dump'])
    if context_regex('\\blsass(?:\\.exe)?\\b', blob) and context_any(blob, ['minidump', 'dump', 'readprocessmemory', 'procdump', 'comsvcs.dll']):
        tags.extend(['lsass_access', 'credential_dump_attempt', 'memory_dump', 'credential_access'])
    if context_any(blob, ['cryptunprotectdata', 'dpapi', 'masterkey']) and context_any(blob, ['login data', 'local state', 'cookies.sqlite', 'web data', 'protect\\\\']):
        tags.extend(['dpapi_access', 'browser_credential_access', 'browser_profile_access', 'credential_access'])
    if context_any(blob, ['credread', 'credenumerate', 'lsagetlogonsessiondata', 'lsaenumeratelogonsessions']):
        tags.extend(['credential_api_access', 'credential_access'])
    if context_any(blob, ['aws_access_key_id', 'secret_access_key', 'refresh_token', 'access_token']) and context_any(blob, ['http://', 'https://', 'webhook', 'telegram', 'discord', 'socket', 'post ']):
        tags.extend(['token_secret_access', 'token_exfiltration', 'network_exfiltration', 'credential_access'])


def collect_persistence_and_credential_tags(blob: object) -> object:
    """Return persistence, registry, credential, and secret-exfiltration tags."""
    tags: list[str] = []
    _append_service_and_account_persistence_tags(blob, tags)
    _append_scheduled_and_registry_persistence_tags(blob, tags)
    _append_credential_access_tags(blob, tags)
    return tags
