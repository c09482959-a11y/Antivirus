"""Detection-owned pickle opcode execution contracts."""

from Virus_Scan.contracts.no_hook_materialization import no_hook_text

RENPY_PICKLE_EXTENSIONS = frozenset({'.rpa', '.rpy', '.rpyc', '.rpyb', '.rpym', '.rpymc'})
PYTHON_PICKLE_EXTENSIONS = frozenset({'.py', '.pyc', '.pyo'})
_PICKLE_CONTEXT_TERMS = (
    'pickle.loads', 'pickle.load(', 'pickletools', 'pickletools.dis', '__reduce__', '__reduce_ex__',
    'copyreg', 'persistent_load', 'find_class', 'stack_global', 'opcode: global', 'opcode: reduce',
    'global opcode', 'reduce opcode', 'cposix\nsystem', 'cnt\nsystem', 'cos\nsystem',
    'subprocess\npopen', 'builtins\neval', 'builtins\nexec', 'posix\nsystem', 'nt\nsystem',
)
_OPCODE_EXEC_TERMS = (
    'cposix\nsystem', 'cnt\nsystem', 'cos\nsystem', 'posix\nsystem', 'nt\nsystem',
    'subprocess\npopen', 'builtins\neval', 'builtins\nexec',
)
_EXEC_CONTEXT_TERMS = (
    'os.system', 'subprocess', 'popen(', 'subprocess.popen', 'subprocess.run', 'eval(', 'exec(',
    'compile(', 'cmd.exe', 'powershell', 'createprocess', 'shell=true', 'runpy.run_path',
    'importlib.import_module',
)


def detect_python_pickle_opcode_exec(text: object, ext: object='') -> object:
    """Return pickle opcode execution tags without depending on scanner-owned helpers."""
    raw_text, text_reason = no_hook_text(text, missing_reason='missing_pickle_opcode_text', unsupported_reason='unsafe_pickle_opcode_text_rejected')
    raw_ext, ext_reason = no_hook_text(ext, missing_reason='missing_pickle_extension_text', unsupported_reason='unsafe_pickle_extension_text_rejected')
    low = raw_text.lower() if text_reason == '' else ''
    extension = raw_ext.lower() if ext_reason == '' else ''
    if extension not in PYTHON_PICKLE_EXTENSIONS | {'.rpy', '.rpyc', '.rpyb'}:
        return []
    pickle_context = any(term in low for term in _PICKLE_CONTEXT_TERMS)
    opcode_exec_context = any(term in low for term in _OPCODE_EXEC_TERMS)
    exec_context = opcode_exec_context or any(term in low for term in _EXEC_CONTEXT_TERMS)
    if not (pickle_context and exec_context):
        return []
    tags = [
        'pickle_deserialization_context', 'pickle_callable_reference',
        'script_execution', 'process_exec', 'python_bytecode_or_script',
    ]
    if 'reduce' in low or '__reduce__' in low or '__reduce_ex__' in low:
        tags.append('pickle_reduce_opcode')
    if opcode_exec_context:
        tags.append('pickle_dangerous_global')
    if extension in {'.rpy', '.rpyc', '.rpyb'}:
        tags.extend(['renpy', 'renpy_script'])
    return tags


__all__ = ('RENPY_PICKLE_EXTENSIONS', 'PYTHON_PICKLE_EXTENSIONS', 'detect_python_pickle_opcode_exec')
