"""Bounded tag-classification ownership helpers.

Split from the former oversized classification module so each file owns one
classification domain with one owned implementation and no duplicate execution path.
"""

ASSET_RESOURCE_FETCH_TERMS = ('xmlhttprequest', 'fetch(', 'image.src', 'audio.src', 'video.src', '.src =', 'fs.writefile')
ASSET_RESOURCE_PATH_TERMS = ('assets/', 'www/', 'game/', '.png', '.jpg', '.ogg', '.mp3', '.json', '.rpa', '.assets')
RESOURCE_CACHE_TERMS = ('cache', 'cached', 'persistentdatapath', 'localstorage', 'indexeddb')
REMOTE_PAYLOAD_DOWNLOAD_TERMS = ('download', 'downloadstring', 'downloadfile', 'fetch(', 'xmlhttprequest', 'urlopen', 'invoke-webrequest')
REMOTE_PAYLOAD_FILE_TERMS = ('.exe', '.dll', '.ps1', '.bat', '.cmd', 'payload', 'stage', 'temp', 'appdata')
C2_TASKING_TERMS = ('command', 'cmd', 'task', 'tasking', 'beacon', 'checkin', 'heartbeat', 'shell')
COMMAND_EXECUTION_TERMS = ('process.start', 'os.system', 'subprocess', 'child_process', 'exec(', 'eval(', 'powershell', 'cmd.exe')
