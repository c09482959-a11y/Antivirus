"""Canonical immutable file-type routing tables owned by routing.

Routing and binary analysis consume this single static source.
"""
from types import MappingProxyType
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.utils.stages import MEDIA_ASSET_EXTENSIONS, FONT_ASSET_EXTENSIONS, UNITY_CONTAINER_ASSET_EXTENSIONS


def _freeze_table(table: object) -> object:
    return MappingProxyType({key: frozenset(value) for key, value in no_hook_mapping_items(table) or ()})


def _freeze_category_table(table: object) -> object:
    return MappingProxyType(dict(no_hook_mapping_items(table) or ()))


def _extension_magic_table() -> object:
    return _freeze_table({'.mp3': {'mp3_id3', 'mp3_frame'}, '.wav': {'wav_riff'}, '.ogg': {'ogg'}, '.oga': {'ogg'}, '.opus': {'ogg'}, '.flac': {'flac'}, '.mp4': {'mp4_iso_bmff'}, '.m4v': {'mp4_iso_bmff'}, '.m4a': {'mp4_iso_bmff'}, '.mov': {'mp4_iso_bmff', 'quicktime'}, '.avi': {'avi_riff'}, '.webm': {'matroska_webm'}, '.mkv': {'matroska_webm'}, '.png': {'png'}, '.jpg': {'jpeg'}, '.jpeg': {'jpeg'}, '.gif': {'gif'}, '.bmp': {'bmp'}, '.webp': {'webp'}, '.zip': {'zip'}, '.jar': {'zip'}, '.rpa': {'renpy_rpa', 'unknown_binary_blob'}, '.rpyc': {'renpy_rpyc', 'unknown_binary_blob'}, '.rpyb': {'renpy_rpyc', 'unknown_binary_blob'}, '.rpymc': {'renpy_rpyc', 'unknown_binary_blob'}, '.exe': {'pe_mz'}, '.dll': {'pe_mz'}, '.unity3d': {'unity_assetbundle', 'unity_webdata', 'unknown_binary_blob'}, '.bundle': {'unity_assetbundle', 'unity_webdata', 'unknown_binary_blob'}, '.assetbundle': {'unity_assetbundle', 'unity_webdata', 'unknown_binary_blob'}, '.assets': {'unity_serialized_asset', 'unknown_binary_blob'}, '.asset': {'unity_serialized_asset', 'unknown_binary_blob'}, '.resource': {'unity_resource', 'unknown_binary_blob'}, '.resources': {'unity_resource', 'unknown_binary_blob'}, '.ress': {'unity_resource', 'unknown_binary_blob'}, '.txt': {'text', 'text_config', 'script_text'}, '.md': {'text', 'text_config', 'script_text'}, '.csv': {'text', 'text_config', 'script_text'}, '.json': {'json_text', 'text_config', 'text'}, '.xml': {'xml_text', 'text_config', 'text'}, '.html': {'html_text', 'text', 'script_text'}, '.htm': {'html_text', 'text', 'script_text'}, '.ini': {'ini_text', 'text_config', 'text'}, '.cfg': {'ini_text', 'text_config', 'text'}, '.yaml': {'text_config', 'text'}, '.yml': {'text_config', 'text'}, '.py': {'script_text', 'text'}, '.pyw': {'script_text', 'text'}, '.js': {'script_text', 'json_text', 'text'}, '.mjs': {'script_text', 'text'}, '.cjs': {'script_text', 'text'}, '.ps1': {'script_text', 'text'}, '.bat': {'script_text', 'text'}, '.cmd': {'script_text', 'text'}, '.sh': {'script_text', 'text'}, '.vbs': {'script_text', 'text'}, '.rb': {'script_text', 'text'}, '.lua': {'script_text', 'text'}, '.cs': {'script_text', 'text'}, '.rpy': {'script_text', 'text'}, '.rvdata': {'rpgm_marshal', 'unknown_binary_blob'}, '.rvdata2': {'rpgm_marshal', 'unknown_binary_blob'}, '.rxdata': {'rpgm_marshal', 'unknown_binary_blob'}, '.ttf': {'ttf_font', 'unknown_binary_blob'}, '.otf': {'otf_font', 'unknown_binary_blob'}, '.woff': {'woff_font'}, '.woff2': {'woff2_font'}})


def _routable_extension_table() -> object:
    return _freeze_table({'binary': {'.exe', '.dll', '.sys', '.ocx', '.so', '.dylib', '.bin'}, 'archive': {'.zip', '.jar', '.tar', '.gz', '.tgz', '.bz2', '.7z', '.rar', '.rpa'}, 'image': {'.png', '.jpg', '.jpeg', '.bmp', '.webp', '.gif', '.svg'}, 'media': MEDIA_ASSET_EXTENSIONS, 'font': FONT_ASSET_EXTENSIONS, 'unity_asset': UNITY_CONTAINER_ASSET_EXTENSIONS, 'runtime': {'.py', '.pyw', '.js', '.mjs', '.cjs', '.ps1', '.bat', '.cmd', '.sh', '.vbs', '.rb', '.lua', '.cs', '.rpy', '.rpyc', '.rpyb', '.rpymc'}, 'rpgm': {'.rvdata', '.rvdata2', '.rxdata'}, 'text_asset': {'.txt', '.md', '.csv', '.json', '.xml', '.html', '.htm', '.ini', '.cfg', '.yaml', '.yml', '.resx'}})


def _magic_type_category_table() -> object:
    return _freeze_category_table({'pe_mz': 'binary', 'elf': 'binary', 'macho': 'binary', 'zip': 'archive', '7z': 'archive', 'rar': 'archive', 'gzip': 'archive', 'tar': 'archive', 'renpy_rpa': 'archive', 'png': 'image', 'jpeg': 'image', 'gif': 'image', 'bmp': 'image', 'webp': 'image', 'mp3_id3': 'media', 'mp3_frame': 'media', 'wav_riff': 'media', 'ogg': 'media', 'flac': 'media', 'mp4_iso_bmff': 'media', 'quicktime': 'media', 'avi_riff': 'media', 'matroska_webm': 'media', 'unity_assetbundle': 'unity_asset', 'unity_webdata': 'unity_asset', 'unity_serialized_asset': 'unity_asset', 'unity_resource': 'unity_asset', 'renpy_rpyc': 'runtime', 'script_text': 'runtime', 'rpgm_marshal': 'rpgm', 'json_text': 'text_asset', 'xml_text': 'text_asset', 'html_text': 'text_asset', 'ini_text': 'text_asset', 'text_config': 'text_asset', 'text': 'text_asset', 'ttf_font': 'font', 'otf_font': 'font', 'woff_font': 'font', 'woff2_font': 'font'})


EXPECTED_MAGIC_TYPES_BY_EXTENSION = _extension_magic_table()
ROUTABLE_EXTENSIONS_BY_CLAIM = _routable_extension_table()
ALL_ROUTABLE_EXTENSIONS = frozenset().union(*(value for _key, value in no_hook_mapping_items(ROUTABLE_EXTENSIONS_BY_CLAIM) or ()))
MAGIC_TYPE_CATEGORY = _magic_type_category_table()
__all__ = ('ALL_ROUTABLE_EXTENSIONS', 'EXPECTED_MAGIC_TYPES_BY_EXTENSION', 'MAGIC_TYPE_CATEGORY', 'ROUTABLE_EXTENSIONS_BY_CLAIM')
