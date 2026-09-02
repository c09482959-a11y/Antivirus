"""Immutable policy tables for target-level game-engine routing detection."""

from types import MappingProxyType

RPGM_CORE_FILES = (
    'www/js/rpg_core.js',
    'www/js/rpg_managers.js',
    'www/js/rpg_objects.js',
    'www/js/rpg_scenes.js',
    'www/js/rmmz_core.js',
    'www/js/rmmz_managers.js',
    'www/js/plugins.js',
    'www/js/plugins/pluginmanager.js',
    'rpg_core.js',
    'rmmz_core.js',
)
RPGM_DATA_FILES = (
    'www/data/actors.json',
    'www/data/system.json',
    'www/data/classes.json',
    'www/data/mapinfos.json',
    'data/actors.json',
    'data/system.json',
    'data/classes.json',
    'data/mapinfos.json',
)
RPGM_RUNTIME_FILES = ('package.json', 'nw.exe', 'node.dll', 'nw.dll', 'www/package.json')
RPGM_ENCRYPTED_EXTENSIONS = ('.png_', '.jpg_', '.jpeg_', '.ogg_', '.m4a_', '.rpgmvp', '.rpgmvm', '.rpgmvo')
RGSS_EXTENSIONS = ('.rvdata', '.rvdata2', '.rxdata', '.rgssad', '.rgss2a', '.rgss3a')
UNITY_CODE_FILES = ('managed/assembly-csharp.dll', 'gameassembly.dll', 'unitycrashhandler64.exe', 'unitycrashhandler32.exe')
RENPY_EXTENSIONS = ('.rpy', '.rpyc', '.rpyb', '.rpa')
PRIORITY_BASENAMES = frozenset({'package.json', 'system.json', 'rpg_core.js', 'rmmz_core.js', 'globalgamemanagers'})
PRIORITY_EXTENSIONS = ('.exe', '.dll', '.js', '.json', '.rpy', '.rpyc')
INITIAL_SCORES = MappingProxyType({'unity': 0.0, 'renpy': 0.0, 'rpgm': 0.0, 'media': 0.0, 'unknown': 0.1})
