"""RenPy source pickle-injection detection owner."""

from dataclasses import dataclass

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage
from Virus_Scan.detection.enrichment.text_boundary import detection_enrichment_text_or_empty


@dataclass(frozen=True, slots=True)
class _RenpyPickleContexts:
    pickle_context: bool
    decode_context: bool
    exec_context: bool
    file_context: bool
    executable_context: bool
    script_context: bool




def _renpy_pickle_contexts(low: str) -> _RenpyPickleContexts:
    return _RenpyPickleContexts(
        pickle_context=any(item in low for item in (
            "pickle.loads", "pickle.load(", "cpickle.loads", "cpickle.load(", "persistent_load", "find_class",
            "__reduce__", "__reduce_ex__", "copyreg", "pickletools", "stack_global", "global opcode", "reduce opcode",
        )),
        decode_context=any(item in low for item in ("base64.b64decode", "zlib.decompress", "gzip.decompress", "marshal.loads", "frombase64string")),
        exec_context=any(item in low for item in ("exec(", "eval(", "compile(", "os.system", "subprocess", "popen(", "cmd.exe", "powershell", "createprocess")),
        file_context=any(item in low for item in ("urlopen", "urlretrieve", "requests.get", "requests.post", "http://", "https://", "open(", "appdata", "%temp%", "renpy.loader")),
        executable_context=any(item in low for item in (".exe", ".dll", "createprocess", "shellexecute", "startfile", "subprocess", "popen(", "cmd.exe", "powershell")),
        script_context=any(item in low for item in (".py", ".pyw", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", "exec(", "eval(", "compile(")),
    )




def _append_renpy_pickle_reference_tags(tags: list[object], contexts: _RenpyPickleContexts) -> None:
    if contexts.pickle_context:
        tags.extend(("pickle_usage", "pickle_deserialization_context"))
    if contexts.pickle_context and contexts.file_context:
        tags.extend(("pickle_file_load_context", "pickle_external_file_reference"))
    if contexts.pickle_context and contexts.executable_context:
        tags.extend(("pickle_external_executable_reference", "process_exec"))
    if contexts.pickle_context and contexts.script_context:
        tags.extend(("pickle_external_script_reference", "python_bytecode_or_script", "script_execution"))
    if contexts.pickle_context and contexts.decode_context:
        tags.extend(("payload_decode_candidate", "encoded_payload_candidate"))


def _append_renpy_pickle_execution_tags(tags: list[object], contexts: _RenpyPickleContexts) -> None:
    if contexts.pickle_context and contexts.exec_context:
        tags.extend((
            "pickle_source_injection_candidate", "pickle_callable_reference",
            "pickle_dangerous_global", "script_execution", "process_exec",
            "renpy", "renpy_script",
        ))
        if contexts.executable_context:
            tags.extend(("pickle_external_executable_reference", "pickle_file_load_context"))
        if contexts.script_context:
            tags.extend(("pickle_external_script_reference", "python_bytecode_or_script"))
    elif contexts.pickle_context and contexts.decode_context and contexts.file_context:
        tags.extend((
            "pickle_source_injection_candidate", "pickle_embedded_payload_candidate",
            "payload_decode_candidate", "encoded_payload_candidate",
        ))


def _append_renpy_pickle_context_tags(tags: list[object], contexts: _RenpyPickleContexts) -> None:
    _append_renpy_pickle_reference_tags(tags, contexts)
    _append_renpy_pickle_execution_tags(tags, contexts)


def renpy_source_pickle_injection_tags(text: object, path: object = None) -> object:
    """Detect unsafe pickle injection patterns in Ren'Py source text."""
    tags: list[object] = []
    try:
        low = detection_enrichment_text_or_empty(text).lower()
        ext = get_scan_extension(path) if path else ""
        path_text = detection_enrichment_text_or_empty(path).lower()
        if ext not in {".rpy", ".rpyc", ".rpyb", ".rpymc", ".py", ".rpym"} and "renpy" not in path_text:
            return []
        contexts = _renpy_pickle_contexts(low)
        _append_renpy_pickle_context_tags(tags, contexts)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        tags.extend(failure_tags_for_stage("renpy_source_pickle_injection", error, context=path))
    return ordered_unique_tags(tags)
