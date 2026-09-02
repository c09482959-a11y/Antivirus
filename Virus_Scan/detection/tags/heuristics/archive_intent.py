"""Bounded tag-classification ownership helpers.

Split from the former oversized classification module so each file owns one
classification domain with one owned implementation and no duplicate execution path.
"""

from pathlib import Path

from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.utils.text_validation import tag_validation_text as _tag_validation_text
from Virus_Scan.utils.text_validation import text_boundary_value as _text_boundary_value
from Virus_Scan.detection.contracts.string_predicates import has_any_text as _has_any_text


def classify_archive_intent_tags(blob: object, path: object=None) -> object:
    text = _tag_validation_text(blob)
    path_text = _text_boundary_value(path, unsupported="") or ""
    name = Path(path_text).name.lower() if path_text else ''
    tags = []
    archive_ctx = _has_any_text(text, ['zipfile', 'zipfile.zipfile', 'tarfile', 'gzip', 'zip_deflated', 'zf.read', 'zf.write', 'infolist', 'namelist', 'pk\x03\x04'])
    save_ctx = _has_any_text(text, ['save', 'savegame', 'savegames', 'slotname', 'persistent', 'loadsave', 'renpy.savegame_suffix', 'clear_slot', 'safe_rename', 'screenshot.png', 'extra_info', 'save location', 'savelocation', 'persistent_mtime']) or name == 'savelocation.py'
    renpy_save_ctx = _has_any_text(text, ['renpy.loadsave', 'filelocation', 'multilocation', 'renpy.config.savedir', 'renpy.config.save', 'renpy.persistent', 'load_persistent', 'save_persistent']) or name == 'savelocation.py'
    if archive_ctx and save_ctx:
        tags.append('save_archive_access')
    if renpy_save_ctx:
        tags.append('renpy_save_location')
    if _has_any_text(text, ['persistent', 'persistent_mtime', 'load_persistent', 'save_persistent']):
        tags.append('persistent_save_data')
    payload_ctx = _has_any_text(text, ['.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.scr', '.msi', 'writeallbytes', 'createfile', '%temp%', 'appdata', 'startup', 'currentversion\run'])
    write_or_extract_ctx = _has_any_text(text, ['extractall', 'extract(', 'writeallbytes', 'createfile', 'copyfile', 'movefile', 'safe_extract', 'unpack', 'decompress'])
    exec_or_persist_ctx = _has_any_text(text, ['start-process', 'createprocess', 'shellexecute', 'cmd.exe', 'powershell', 'subprocess', 'os.system', 'popen(', 'schtasks', 'service create', 'currentversion\run', 'startup'])
    if archive_ctx and payload_ctx and write_or_extract_ctx and exec_or_persist_ctx:
        tags.extend(['archive_dropper', 'embedded_archive_payload', 'dropper_behavior'])
    return ordered_unique_tags(tags)
