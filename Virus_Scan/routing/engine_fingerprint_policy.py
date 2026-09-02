"""Immutable engine fingerprint policy tables."""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

ENGINE_NAMES = ("renpy", "rpgm", "unity", "media", "other")

RENPY_EXTENSIONS = (".rpy", ".rpyc", ".rpyb", ".rpymc", ".rpa")
RENPY_FILENAMES = (
    "archive.rpa", "scripts.rpa", "fonts.rpa", "audio.rpa", "images.rpa",
    "script.rpy", "screens.rpy", "options.rpy", "gui.rpy", "audio.rpy",
    "renpy.exe", "renpy.py", "renpy.sh", "librenpy.so", "python27.dll", "python36.dll",
    "python37.dll", "python38.dll", "python39.dll", "python310.dll", "python311.dll",
    "python312.dll", "pythonw.exe", "libpython2.7.so", "libpython3.7m.so",
    "libpython3.9.so", "libpython3.10.so", "libpython3.11.so", "persistent", "persistent.save",
    "traceback.txt", "errors.txt", "android.json",
)
RENPY_PATH_MARKERS = (
    "/game/", "/renpy/", "/renpy/common/", "/launcher/", "/tl/", "/saves/",
    "/rapt/", "/renpyandroid/",
)
RENPY_EXACT_PATHS = (
    "renpy/common/00library.rpy", "renpy/common/00action_menu.rpy",
    "renpy/common/00preferences.rpy",
)
RENPY_PATTERNS = ("*.rpa", "*.rpy", "*.rpyc", "game/*.rpy", "renpy/common/*.rpy")
RENPY_CONTENT_MARKERS = (
    "renpy", "init python", "label start", "screen ", "jump ", "call screen",
    "marshal.loads",
    "base64.b64decode", "renpy.bootstrap", "renpy.exports",
)

RPGM_EXTENSIONS = (
    ".rxdata", ".rvdata", ".rvdata2", ".rpgmvp", ".rpgmvo", ".rpgmvm",
    ".rpgsave", ".lmu", ".lsd", ".ldb", ".lmt", ".rgssad", ".rgss2a", ".rgss3a",
)
RPGM_FILENAMES = (
    "rgss102e.dll", "rgss100j.dll", "rgss200e.dll", "rgss202e.dll", "rgss300.dll",
    "rgss301.dll", "game.rxproj", "game.rvproj", "game.rvproj2", "game.rmmzproject",
    "game.ini", "game.rgssad", "game.rgss2a", "game.rgss3a", "rpg_rt.exe", "rpg2000rtp.exe", "rpg2003rtp.exe", "rpg_rt.ini",
    "rpg_rt.ldb", "rpg_rt.lmt", "nw.dll", "node.dll", "nw.exe", "game.exe",
    "package.json", "index.html", "rpg_core.js", "rpg_managers.js", "rpg_objects.js",
    "rpg_scenes.js", "rpg_sprites.js", "rpg_windows.js", "rmmz_core.js",
    "rmmz_managers.js", "rmmz_objects.js", "rmmz_scenes.js", "rmmz_sprites.js",
    "rmmz_windows.js", "plugins.js", "main.js", "actors.json", "classes.json",
    "system.json", "mapinfos.json", "map001.json", "global.rpgsave", "config.rpgsave",
    "app.asar", "nw_elf.dll", "icudtl.dat", "ffmpeg.dll",
)
RPGM_PATH_MARKERS = (
    "/data/", "/www/", "/www/js/", "/www/data/", "/www/img/", "/www/audio/",
    "/js/plugins/",
)
RPGM_PATTERNS = (
    "data/*.rxdata", "data/*.rvdata", "data/*.rvdata2", "data/actors.rxdata", "data/actors.rvdata", "data/actors.rvdata2", "map*.lmu", "save*.lsd",
    "www/js/*.js", "www/data/*.json", "file*.rpgsave", "map*.json", "*.rpgmvp",
    "*.rpgmvo", "*.rpgmvm",
)
RPGM_CONTENT_MARKERS = ("rpgmaker", "rpg_core", "rmmz_core", "rgss", "game_title", "www/js", "game_interpreter")

UNITY_EXTENSIONS = (
    ".assets", ".ress", ".resource", ".unity", ".bundle", ".unity3d", ".unityweb",
    ".wasm", ".pdb",
)
UNITY_FILENAMES = (
    "unityplayer.dll", "unitycrashhandler64.exe", "unitycrashhandler32.exe", "unityplayer.so",
    "libunity.so", "unityframework.framework", "gameassembly.dll", "gameassembly.pdb", "global-metadata.dat",
    "libil2cpp.so", "assembly-csharp.dll", "assembly-csharp-firstpass.dll",
    "assembly-unityscript.dll", "unityengine.dll", "unityengine.coremodule.dll", "mono.dll",
    "mono-2.0-bdwgc.dll", "level0", "resources.assets", "resources.assets.ress",
    "globalgamemanagers", "globalgamemanagers.assets", "globalgamemanagers.resources",
    "maindata", "data.unity3d", "projectversion.txt", "editorbuildsettings.asset", "unity default resources",
    "boot.config", "inputmanager.asset", "tagmanager.asset", "timemanager.asset",
    "catalog.json", "settings.json", "build.loader.js", "build.framework.js", "build.data",
    "build.wasm", "unityloader.js", "unity default resources",
)
UNITY_PATH_MARKERS = (
    "/metadata/global-metadata.dat", "/il2cpp_data/", "/unityframework.framework/", "/monobleedingedge/",
    "/monobleedingedge/etc/mono/config", "/monobleedingedge/embedruntimes/", "_data/",
    "/managed/", "/resources/", "/streamingassets/", "/plugins/", "/assets/",
    "/projectsettings/", "/library/", "/packages/", "/usersettings/", "/assets/bin/data/",
    "/assets/bin/data/managed/",
)
UNITY_PATTERNS = (
    "*_data/*", "*_data/managed/*", "managed/*.dll", "streamingassets/*", "plugins/*",
    "sharedassets*.assets", "sharedassets*.resource", "*.assets.ress", "*.ress", "cab-*",
    "*.wasm.framework.unityweb", "*.data.unityweb", "*.wasm.code.unityweb", "*.symbols.json", "*.bundle", "*.unity3d",
    "build/*.data", "build/*.wasm", "build/*.framework.js", "assets/bin/data/*",
)
UNITY_CONTENT_MARKERS = (
    "unityplayer", "assembly-csharp", "global-metadata", "il2cpp", "monobleedingedge",
    "unityengine", "unityfs", "unityweb", "serializedfile",
)

MEDIA_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".ico",
    ".dds", ".ktx", ".ktx2", ".pvr", ".qoi", ".tga", ".ogg", ".mp3", ".wav",
    ".oga", ".opus", ".flac", ".mp4", ".m4v", ".m4a", ".mov", ".avi", ".webm", ".mkv",
)
MEDIA_FILENAMES: tuple[str, ...] = ()
MEDIA_PATH_MARKERS = ("/images/", "/audio/", "/music/", "/sfx/", "/movies/", "/video/", "/www/img/", "/www/audio/")
MEDIA_PATTERNS = ("images/*", "audio/*", "music/*", "sfx/*", "movies/*", "video/*", "www/img/*", "www/audio/*")
MEDIA_CONTENT_MARKERS: tuple[str, ...] = ()


DIRECT_CONTAINER_DIRECTORY_MARKERS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "renpy": ("game", "renpy", "launcher", "tl", "saves", "rapt", "renpyandroid"),
    "rpgm": ("www", "data"),
    "unity": ("managed", "resources", "streamingassets", "plugins", "assets", "projectsettings", "library", "packages", "usersettings"),
    "media": ("images", "audio", "music", "video", "videos", "sound", "sounds"),
})


ENGINE_FINGERPRINTS: Mapping[str, Mapping[str, tuple[str, ...]]] = MappingProxyType({
    "renpy": MappingProxyType({"extensions": RENPY_EXTENSIONS, "filenames": RENPY_FILENAMES, "path_markers": RENPY_PATH_MARKERS, "exact_paths": RENPY_EXACT_PATHS, "patterns": RENPY_PATTERNS, "content_markers": RENPY_CONTENT_MARKERS}),
    "rpgm": MappingProxyType({"extensions": RPGM_EXTENSIONS, "filenames": RPGM_FILENAMES, "path_markers": RPGM_PATH_MARKERS, "exact_paths": (), "patterns": RPGM_PATTERNS, "content_markers": RPGM_CONTENT_MARKERS}),
    "unity": MappingProxyType({"extensions": UNITY_EXTENSIONS, "filenames": UNITY_FILENAMES, "path_markers": UNITY_PATH_MARKERS, "exact_paths": (), "patterns": UNITY_PATTERNS, "content_markers": UNITY_CONTENT_MARKERS}),
    "media": MappingProxyType({"extensions": MEDIA_EXTENSIONS, "filenames": MEDIA_FILENAMES, "path_markers": MEDIA_PATH_MARKERS, "exact_paths": (), "patterns": MEDIA_PATTERNS, "content_markers": MEDIA_CONTENT_MARKERS}),
})

__all__ = (
    "DIRECT_CONTAINER_DIRECTORY_MARKERS",
    "ENGINE_FINGERPRINTS",
    "ENGINE_NAMES",
    "MEDIA_CONTENT_MARKERS",
    "MEDIA_EXTENSIONS",
    "MEDIA_FILENAMES",
    "MEDIA_PATH_MARKERS",
    "MEDIA_PATTERNS",
    "RENPY_CONTENT_MARKERS",
    "RENPY_EXACT_PATHS",
    "RENPY_EXTENSIONS",
    "RENPY_FILENAMES",
    "RENPY_PATH_MARKERS",
    "RENPY_PATTERNS",
    "RPGM_CONTENT_MARKERS",
    "RPGM_EXTENSIONS",
    "RPGM_FILENAMES",
    "RPGM_PATH_MARKERS",
    "RPGM_PATTERNS",
    "UNITY_CONTENT_MARKERS",
    "UNITY_EXTENSIONS",
    "UNITY_FILENAMES",
    "UNITY_PATH_MARKERS",
    "UNITY_PATTERNS",
)
