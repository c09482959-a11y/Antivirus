"""Ordinary source-text pickle opcode execution detection."""
from __future__ import annotations

from Virus_Scan.scanners.contracts import scanner_contract_text

pickle_context_needles = (
    'pickle.loads', 'pickle.load(', 'pickletools', 'pickletools.dis', '__reduce__',
    '__reduce_ex__', 'copyreg', 'persistent_load', 'find_class', 'stack_global',
    'opcode: global', 'opcode: reduce', 'global opcode', 'reduce opcode',
    'cposix\nsystem', 'cnt\nsystem', 'cos\nsystem', 'subprocess\npopen',
    'builtins\neval', 'builtins\nexec', 'posix\nsystem', 'nt\nsystem',
)
opcode_exec_needles = (
    'cposix\nsystem', 'cnt\nsystem', 'cos\nsystem', 'posix\nsystem',
    'nt\nsystem', 'subprocess\npopen', 'builtins\neval', 'builtins\nexec',
)
source_exec_needles = (
    'os.system', 'subprocess', 'popen(', 'subprocess.popen', 'subprocess.run',
    'eval(', 'exec(', 'compile(', 'cmd.exe', 'powershell', 'createprocess',
    'shell=true', 'runpy.run_path', 'importlib.import_module',
)
source_pickle_extensions = frozenset(('.py', '.pyc', '.pyo', '.rpy', '.rpyc', '.rpyb'))
renpy_source_extensions = frozenset(('.rpy', '.rpyc', '.rpyb'))


def detect_python_pickle_opcode_exec(text: object, ext: object = '') -> object:
    """Detect unsafe pickle opcode/deserialization execution in ordinary Python source/bytecode."""
    low = scanner_contract_text(text, replacement='').lower()
    ext = scanner_contract_text(ext, replacement='').lower()
    if ext not in source_pickle_extensions:
        return []
    pickle_context = any(x in low for x in pickle_context_needles)
    opcode_exec_context = any(x in low for x in opcode_exec_needles)
    exec_context = opcode_exec_context or any(x in low for x in source_exec_needles)
    if pickle_context and exec_context:
        tags = [
            'pickle_deserialization_context', 'pickle_callable_reference',
            'script_execution', 'process_exec', 'python_bytecode_or_script',
        ]
        if 'reduce' in low or '__reduce__' in low or '__reduce_ex__' in low:
            tags.append('pickle_reduce_opcode')
        if opcode_exec_context:
            tags.append('pickle_dangerous_global')
        if ext in renpy_source_extensions:
            tags.extend(['renpy', 'renpy_script'])
        return tags
    return []


__all__ = ('detect_python_pickle_opcode_exec',)
