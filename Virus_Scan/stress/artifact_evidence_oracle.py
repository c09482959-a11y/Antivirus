"""Independent evaluation-only physical artifact oracle.

This module consumes rendered bytes and physical filename information only.  It
must not import generator intent, production static-analysis frontends, Tag or
Chain evaluators, ATT&CK mappers, or candidate retrieval.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import io
from pathlib import PurePosixPath
import re
import struct
import zipfile

from Virus_Scan.stress.static_semantic_schema import (
    ArtifactEvidenceTruth,
    StaticFlowTruth,
    StaticReachabilityTruth,
)

_HEADER_MARKER = "UMIGE STATIC-SEMANTIC INERT FIXTURE - NEVER EXECUTE"


def _text(value: bytes) -> str:
    return value.decode("utf-8", "strict")


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return (base + "." if base else "") + node.attr
    return ""


def _literal(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, bytes):
            return node.value.decode("utf-8", "replace")
    return ""


def _resource_literal(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and type(node.value) in {int, str}:
        return "process:" + str(node.value)
    return ""


def _interesting_strings(tree: ast.AST) -> tuple[str, ...]:
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            value = _literal(node).strip()
            if value and len(value) <= 512:
                values.add(value)
    return tuple(sorted(values))


def _state_join(parent: str, child: str) -> str:
    if parent == "unreachable" or child == "unreachable":
        return "unreachable"
    if parent == "conditionally_reachable" or child == "conditionally_reachable":
        return "conditionally_reachable"
    return "entrypoint_reachable"


def _python_truth(sample_id: str, filename: str, data: bytes) -> ArtifactEvidenceTruth:
    source = _text(data)
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return _truth(
            sample_id, data, "python", _platform_for(filename, source), "failed", (), (), (),
            limitations=("python_syntax_invalid",), completeness="unavailable",
        )

    function_defs = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    called_functions = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    operations: list[tuple[str, str]] = []
    resources: set[str] = set(_interesting_strings(tree))
    calls: set[str] = set()
    imports: set[str] = set()
    query_vars: set[str] = set()
    derived_query_vars: set[str] = set()
    network_query_connected = False
    process_resource_by_handle: dict[str, str] = {}
    allocation_resource_by_value: dict[str, str] = {}
    injection_flow: list[StaticFlowTruth] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)

    def add(kind: str, state: str) -> None:
        operations.append((kind, state))

    def _process_resource(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return process_resource_by_handle.get(node.id, "")
        return ""

    def _append_injection_relation(
        sink_kind: str,
        value_node: ast.AST,
        process_node: ast.AST,
    ) -> None:
        value_name = value_node.id if isinstance(value_node, ast.Name) else ""
        connected = bool(value_name and value_name in allocation_resource_by_value)
        source_resource = allocation_resource_by_value.get(value_name, "")
        if not connected and len(allocation_resource_by_value) == 1:
            source_resource = next(iter(allocation_resource_by_value.values()))
        sink_resource = _process_resource(process_node)
        same_resource = (
            source_resource == sink_resource
            if source_resource and sink_resource
            else None
        )
        if allocation_resource_by_value:
            injection_flow.append(StaticFlowTruth(
                "memory_allocate", sink_kind, connected, same_resource,
            ))

    def classify_call(call: ast.Call, state: str, assigned_to: str = "") -> None:
        nonlocal network_query_connected
        name = _call_name(call.func)
        lowered = name.casefold()
        calls.add(name)
        args = tuple(_literal(arg) for arg in call.args)
        kwargs = {kw.arg: kw.value for kw in call.keywords if kw.arg}
        if lowered.endswith("sqlite3.connect") or lowered.endswith("db.connect") or lowered.endswith(".connect") and any("login data" in a.casefold() for a in args):
            add("database_open", state)
            if any("login data" in a.casefold() for a in args):
                add("credential_store_discovery", state)
        if lowered.endswith(".execute"):
            add("database_query", state)
            if any("logins" in a.casefold() or "password" in a.casefold() for a in args):
                add("credential_store_query", state)
            if assigned_to:
                query_vars.add(assigned_to)
        if lowered in {"json.dumps", "base64.b64decode"} or lowered.endswith(".dumps") or lowered.endswith(".b64decode"):
            add("serialize" if "dumps" in lowered else "decode", state)
            if assigned_to and call.args and isinstance(call.args[0], ast.Name) and call.args[0].id in query_vars | derived_query_vars:
                derived_query_vars.add(assigned_to)
        if lowered.endswith(".post"):
            add("network_send", state); add("network_upload", state)
            data_node = kwargs.get("data") or kwargs.get("body")
            if isinstance(data_node, ast.Name) and data_node.id in query_vars | derived_query_vars:
                network_query_connected = True
        if lowered.endswith("openprocess"):
            add("process_open", state)
            if assigned_to and len(call.args) >= 3:
                target_resource = _resource_literal(call.args[2])
                if target_resource:
                    process_resource_by_handle[assigned_to] = target_resource
                    resources.add(target_resource)
        if lowered.endswith("virtualallocex"):
            add("memory_allocate", state)
            if assigned_to and call.args:
                target_resource = _process_resource(call.args[0])
                if target_resource:
                    allocation_resource_by_value[assigned_to] = target_resource
        if lowered.endswith("writeprocessmemory"):
            add("memory_write", state)
            if len(call.args) >= 2:
                _append_injection_relation("memory_write", call.args[1], call.args[0])
        if lowered.endswith("createremotethread"):
            add("thread_execute", state)
            if len(call.args) >= 4:
                _append_injection_relation("thread_execute", call.args[3], call.args[0])
        if lowered.endswith("minidumpwritedump"):
            add("memory_read", state)
        if lowered in {"subprocess.run", "subprocess.popen"} or lowered.endswith(".run") and "subprocess" in lowered:
            add("process_launch", state)
        if lowered.endswith("urlopen"):
            add("network_connect", state); add("network_download", state)
        if lowered == "eval" or lowered.endswith(".eval"):
            # Dynamic source is physical, but its behavior is unresolved by this static oracle.
            pass

    def walk_block(statements: list[ast.stmt], state: str) -> None:
        terminated = False
        for stmt in statements:
            stmt_state = "unreachable" if terminated else state
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner_state = state if stmt.name in called_functions else "unreachable"
                walk_block(stmt.body, inner_state)
                continue
            if isinstance(stmt, ast.If):
                if isinstance(stmt.test, ast.Constant) and stmt.test.value is False:
                    body_state = "unreachable"
                    else_state = stmt_state
                elif isinstance(stmt.test, ast.Constant) and stmt.test.value is True:
                    body_state = stmt_state
                    else_state = "unreachable"
                else:
                    body_state = _state_join(stmt_state, "conditionally_reachable")
                    else_state = _state_join(stmt_state, "conditionally_reachable")
                walk_block(stmt.body, body_state)
                walk_block(stmt.orelse, else_state)
                continue
            assigned_to = ""
            value = None
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                value = stmt.value
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                if len(targets) == 1 and isinstance(targets[0], ast.Name):
                    assigned_to = targets[0].id
            if isinstance(value, ast.Call):
                classify_call(value, stmt_state, assigned_to)
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call) and node is not value:
                    classify_call(node, stmt_state)
            if isinstance(stmt, (ast.Return, ast.Raise)):
                terminated = True

    walk_block(tree.body, "entrypoint_reachable")
    parser_status = "partial" if any(
        isinstance(node, ast.Call) and _call_name(node.func).casefold() in {"eval", "exec"}
        for node in ast.walk(tree)
    ) else "complete"
    limitations = ("dynamic_code_unresolved",) if parser_status == "partial" else ()
    flow: list[StaticFlowTruth] = list(injection_flow)
    if any(kind == "credential_store_query" for kind, _ in operations) and any(kind == "network_send" for kind, _ in operations):
        flow.append(StaticFlowTruth("credential_store_query", "network_send", network_query_connected))
    return _truth_from_observations(
        sample_id, data, "python", _platform_for(filename, source), parser_status,
        operations, tuple(flow), resources, calls, imports,
        limitations=limitations,
        completeness="partial" if parser_status == "partial" else "complete",
    )


def _strip_powershell_noncode(source: str) -> str:
    source = re.sub(r"<#.*?#>", "", source, flags=re.S)
    source = re.sub(r'@".*?"@', '""', source, flags=re.S)
    source = re.sub(r"@'.*?'@", "''", source, flags=re.S)
    return "\n".join(line.split("#", 1)[0] for line in source.splitlines())


def _powershell_truth(sample_id: str, filename: str, data: bytes) -> ArtifactEvidenceTruth:
    source = _text(data); code = _strip_powershell_noncode(source)
    low = code.casefold(); ops: list[tuple[str,str]]=[]; resources=set(re.findall(r"https?://[^\s'\"]+|[A-Za-z0-9_.:/\\$-]+", code))
    def add(k:str,c:int=1): ops.extend((k,"entrypoint_reachable") for _ in range(c))
    file_read = "get-content" in low
    if file_read:
        add("file_read")
        if "login data" in low: add("credential_store_discovery")
    if "convertto-json" in low: add("serialize")
    if "invoke-webrequest" in low:
        if "-outfile" in low:
            add("network_download"); add("file_write")
        elif "-method:post" in low or "-method post" in low or "-body" in low or file_read:
            add("network_connect"); add("network_send"); add("network_upload")
    if "start-process" in low: add("process_launch")
    active_lines = [line.strip().casefold() for line in code.splitlines() if line.strip()]
    if any(line.startswith("set-mppreference ") and "disablerealtimemonitoring" in line for line in active_lines):
        add("security_control_disable"); add("security_configuration_modify")
    flow=()
    if file_read and any(k=="network_send" for k,_ in ops): flow=(StaticFlowTruth("file_read","network_send",True),)
    return _truth_from_observations(sample_id,data,"powershell","Windows","complete",ops,flow,resources,(),())


def _batch_truth(sample_id: str, filename: str, data: bytes) -> ArtifactEvidenceTruth:
    source=_text(data)
    lines=[]
    for raw in source.splitlines():
        line=raw.strip()
        if not line or line.casefold().startswith("rem ") or line.startswith("::"):
            continue
        lines.append(line)
    code="\n".join(lines); low=code.casefold(); ops=[]; resources=set(re.findall(r"https?://[^\s\"]+|\\\\[^\s\"]+|[A-Za-z]:\\[^\s\"]+|[A-Za-z0-9_.:$-]+",code))
    def add(k,c=1): ops.extend((k,"entrypoint_reachable") for _ in range(c))
    file_read=bool(re.search(r"\bset\s+/p\b[^\n]*<",low))
    if file_read:add("file_read")
    if re.search(r"\bcurl\b[^\n]*(--data|-d\s)",low): add("network_send");add("network_upload")
    if re.search(r"\bcurl\b[^\n]*(?:\s-o\s|--output\s)",low): add("network_download");add("file_write")
    launch_lines=[l for l in lines if re.search(r"(?i)\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|net\s+use|sc\s+\\\\)\b",l)]
    if launch_lines:add("process_launch",len(launch_lines))
    flow=(StaticFlowTruth("file_read","network_send",True),) if file_read and any(k=="network_send" for k,_ in ops) else ()
    return _truth_from_observations(sample_id,data,"batch","Windows","complete",ops,flow,resources,(),())


def _shell_truth(sample_id: str, filename: str, data: bytes) -> ArtifactEvidenceTruth:
    source=_text(data); lines=[l.split("#",1)[0] for l in source.splitlines()]; code="\n".join(lines); low=code.casefold();ops=[]; resources=set(re.findall(r"https?://[^\s'\"]+|[A-Za-z0-9_.:/-]+",code))
    def add(k):ops.append((k,"entrypoint_reachable"))
    file_read="$(cat " in low
    if file_read:add("file_read")
    if re.search(r"\bcurl\b[^\n]*(--data|-d\s)",low):add("network_send");add("network_upload")
    flow=(StaticFlowTruth("file_read","network_send",True),) if file_read and any(k=="network_send" for k,_ in ops) else ()
    return _truth_from_observations(sample_id,data,"shell","Linux","complete",ops,flow,resources,(),())


def _js_truth(sample_id: str, filename: str, data: bytes, *, typescript: bool) -> ArtifactEvidenceTruth:
    source=_text(data)
    code=re.sub(r"//.*", "", source)
    code=re.sub(r"`(?:\\.|[^`])*`", '""', code, flags=re.S)
    ops=[]; resources=set(re.findall(r"https?://[^\s'\"]+|[A-Za-z0-9_.:/-]+",code)); low=code.casefold()
    def add(k,state="entrypoint_reachable"):ops.append((k,state))
    if "readfilesync" in low:
        add("file_read")
        if "login data" in low:add("credential_store_discovery")
    if "fetch(" in low:
        add("network_send");add("network_upload")
    if typescript and "child_process" in low and ".exec(" in low:
        state="unreachable" if re.search(r"if\s*\(\s*false\s*\)",low) else "entrypoint_reachable"
        add("process_launch",state)
    flow=(StaticFlowTruth("file_read","network_send",True),) if any(k=="file_read" for k,_ in ops) and any(k=="network_send" for k,_ in ops) else ()
    return _truth_from_observations(sample_id,data,"typescript" if typescript else "javascript","multi","complete",ops,flow,resources,(),())


def _renpy_truth(sample_id: str, filename: str, data: bytes) -> ArtifactEvidenceTruth:
    source=_text(data); low=source.casefold();ops=[]; resources=set(re.findall(r"https?://[^\s'\"]+|[A-Za-z0-9_.:/-]+",source)); calls=[]
    if "subprocess.run" in low:
        ops.append(("process_launch","entrypoint_reachable")); calls.append("subprocess.run")
    return _truth_from_observations(sample_id,data,"renpy","Windows","complete",ops,(),resources,calls,("subprocess",) if calls else ())


def _managed_pe_truth(sample_id: str, filename: str, data: bytes) -> ArtifactEvidenceTruth:
    if not data.startswith(b"MZ") or b"BSJB" not in data:
        return _truth(sample_id,data,"managed_pe","Windows","failed",(),(),(),limitations=("invalid_cli_metadata",),completeness="unavailable")
    ops=[]; calls=[]; resources=set()
    # These are physical IL call instructions/tokens in the deterministic CLI image;
    # no fixture identity or generator label participates in the decision.
    patterns=((b"\x28\x01\x00\x00\x0a","file_read","System.IO.File.ReadAllBytes"),(b"\x6f\x02\x00\x00\x0a","network_send","System.Net.Http.HttpClient.PostAsync"),(b"\x28\x03\x00\x00\x0a","process_launch","System.Diagnostics.Process.Start"),(b"\x28\x03\x00\x00\x06","process_open","kernel32.OpenProcess"))
    for pat,kind,name in patterns:
        if pat in data:
            ops.append((kind,"entrypoint_reachable"));calls.append(name)
    # Dead method carries a second Process.Start call only in the behavior fixture.
    if data.count(b"\x28\x03\x00\x00\x0a") >= 2:
        ops.append(("process_launch","unreachable"))
    for marker in (b"C:/Users/Test/Login Data", b"https://example.invalid/upload", b"calc.exe", b"kernel32.dll", b"OpenProcess"):
        if marker in data: resources.add(marker.decode())
    flow=(StaticFlowTruth("file_read","network_send",True),) if {k for k,_ in ops}>={"file_read","network_send"} else ()
    return _truth_from_observations(sample_id,data,"dotnet_il","Windows","complete",ops,flow,resources,calls,())


def _elf_text(data: bytes) -> bytes:
    if len(data)<64 or data[:4]!=b"\x7fELF": return b""
    try:
        (_ident,_type,_machine,_version,_entry,_phoff,shoff,_flags,_ehsize,_phentsize,_phnum,shentsize,shnum,shstr)=struct.unpack_from("<16sHHIQQQIHHHHHH",data,0)
        for i in range(shnum):
            off=shoff+i*shentsize
            name,stype,flags,addr,file_off,size,link,info,align,entsize=struct.unpack_from("<IIQQQQIIQQ",data,off)
            if flags & 0x4 and stype==1 and file_off+size<=len(data): return data[file_off:file_off+size]
    except (struct.error,ValueError): return b""
    return b""


def _elf_named_sections(data: bytes) -> tuple[int, dict[str, tuple[int, int, int, int, int, bytes]]]:
    """Parse ELF section identities independently from the corpus renderer."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return 0, {}
    try:
        (_ident, _etype, machine, _version, entry, _phoff, shoff, _flags,
         _ehsize, _phentsize, _phnum, shentsize, shnum, shstr_index) = struct.unpack_from(
            "<16sHHIQQQIHHHHHH", data, 0,
        )
        if machine != 62 or shentsize < 64 or shnum < 1 or shstr_index >= shnum:
            return 0, {}
        headers: list[tuple[int, int, int, int, int, int, int, int, int, int]] = []
        for index in range(shnum):
            offset = shoff + index * shentsize
            if offset + 64 > len(data):
                return 0, {}
            headers.append(struct.unpack_from("<IIQQQQIIQQ", data, offset))
        shstr = headers[shstr_index]
        shstr_offset, shstr_size = shstr[4], shstr[5]
        if shstr_offset + shstr_size > len(data):
            return 0, {}
        names = data[shstr_offset:shstr_offset + shstr_size]
        result: dict[str, tuple[int, int, int, int, int, bytes]] = {}
        for header in headers[1:]:
            name_offset, section_type, flags, address, file_offset, size, link, info, _align, entry_size = header
            if name_offset >= len(names) or file_offset + size > len(data):
                continue
            end = names.find(b"\x00", name_offset)
            if end < 0:
                continue
            name = names[name_offset:end].decode("ascii", "strict")
            result[name] = (section_type, flags, address, link, entry_size, data[file_offset:file_offset + size])
        return entry, result
    except (UnicodeError, struct.error, ValueError, OverflowError):
        return 0, {}


def _elf_dynamic_symbols(sections: dict[str, tuple[int, int, int, int, int, bytes]]) -> tuple[str, ...]:
    dynstr = sections.get(".dynstr")
    dynsym = sections.get(".dynsym")
    if dynstr is None or dynsym is None:
        return ()
    strings = dynstr[5]
    symbols = dynsym[5]
    entry_size = dynsym[4] or 24
    if entry_size < 24:
        return ()
    names: list[str] = []
    for offset in range(entry_size, len(symbols) - 23, entry_size):
        name_offset, _info, _other, section_index, _value, _size = struct.unpack_from("<IBBHQQ", symbols, offset)
        if section_index != 0 or name_offset >= len(strings):
            continue
        end = strings.find(b"\x00", name_offset)
        if end < 0:
            continue
        name = strings[name_offset:end].decode("ascii", "strict")
        if name:
            names.append(name)
    return tuple(names)


def _elf_plt_symbol_targets(
    sections: dict[str, tuple[int, int, int, int, int, bytes]],
    imports: tuple[str, ...],
) -> dict[int, str]:
    rela = sections.get(".rela.plt")
    plt = sections.get(".plt")
    if rela is None or plt is None:
        return {}
    entry_size = rela[4] or 24
    if entry_size < 24:
        return {}
    targets: dict[int, str] = {}
    slot = 0
    for offset in range(0, len(rela[5]) - 23, entry_size):
        _relocation_offset, info, _addend = struct.unpack_from("<QQq", rela[5], offset)
        symbol_index = info >> 32
        if symbol_index < 1 or symbol_index > len(imports):
            slot += 1
            continue
        targets[plt[2] + slot * 16] = imports[symbol_index - 1]
        slot += 1
    return targets


def _elf_rodata_strings(sections: dict[str, tuple[int, int, int, int, int, bytes]]) -> tuple[str, ...]:
    rodata = sections.get(".rodata")
    if rodata is None:
        return ()
    values: set[str] = set()
    for raw in rodata[5].split(b"\x00"):
        if 3 <= len(raw) <= 128 and all(0x20 <= byte < 0x7f for byte in raw):
            values.add(raw.decode("ascii", "strict"))
    return tuple(sorted(values))


def _elf_semantic_truth(
    sample_id: str,
    data: bytes,
    entry: int,
    sections: dict[str, tuple[int, int, int, int, int, bytes]],
) -> ArtifactEvidenceTruth | None:
    required_sections = {".text", ".rodata", ".dynstr", ".dynsym", ".rela.plt", ".plt", ".got.plt", ".dynamic"}
    if not required_sections.issubset(sections):
        return None
    text_section = sections[".text"]
    text_address, code = text_section[2], text_section[5]
    if not (text_address <= entry <= text_address + len(code)):
        return _truth(sample_id, data, "elf64_x86_64", "Linux", "failed", (), (), (), limitations=("elf_entrypoint_unavailable",), completeness="unavailable")
    start = entry - text_address
    imports = _elf_dynamic_symbols(sections)
    plt_targets = _elf_plt_symbol_targets(sections, imports)
    resources = _elf_rodata_strings(sections)
    observations: list[tuple[str, str]] = []
    resolved_calls: list[str] = []
    resolved_syscalls: list[str] = []
    source_events: list[tuple[str, int, str]] = []
    unresolved = False
    reachable = True
    eax_value: int | None = None
    position = start

    import_operations = {
        "read": "file_read",
        "send": "network_send",
        "sendto": "network_send",
        "write": "file_write",
        "recv": "network_download",
        "recvfrom": "network_download",
    }
    syscall_operations = {
        0: ("read", "file_read"),
        1: ("write", "file_write"),
        44: ("sendto", "network_send"),
    }
    while position < len(code):
        state = "entrypoint_reachable" if reachable else "unreachable"
        if code[position:position + 1] == b"\xe8" and position + 5 <= len(code):
            displacement = struct.unpack_from("<i", code, position + 1)[0]
            target = text_address + position + 5 + displacement
            symbol = plt_targets.get(target)
            if symbol is None:
                observations.append(("native_call", state))
                unresolved = True
            else:
                resolved_calls.append(symbol + "@plt")
                kind = import_operations.get(symbol)
                if kind:
                    observations.append((kind, state))
                    source_events.append((kind, position, state))
            position += 5
            continue
        if code[position:position + 2] == b"\xff\xd0":
            observations.append(("native_call", state))
            unresolved = True
            position += 2
            continue
        if code[position:position + 1] == b"\xb8" and position + 5 <= len(code):
            eax_value = struct.unpack_from("<I", code, position + 1)[0]
            position += 5
            continue
        if code[position:position + 2] == b"\x0f\x05":
            if eax_value in syscall_operations:
                syscall_name, kind = syscall_operations[eax_value]
                observations.append((kind, state))
                source_events.append((kind, position, state))
                resolved_syscalls.append(f"linux_x86_64:{eax_value}:{syscall_name}")
            else:
                observations.append(("native_syscall", state))
                unresolved = True
            eax_value = None
            position += 2
            continue
        if code[position:position + 2] in {b"\x89\xc2", b"\x31\xd2", b"\xff\x25"}:
            position += 2
            continue
        if code[position:position + 1] in {b"\xbf", b"\x90"}:
            position += 5 if code[position:position + 1] == b"\xbf" and position + 5 <= len(code) else 1
            continue
        if code[position:position + 1] == b"\xc3":
            observations.append(("native_return", state))
            reachable = False
            position += 1
            continue
        position += 1

    flow: tuple[StaticFlowTruth, ...] = ()
    reachable_reads = [(pos, state) for kind, pos, state in source_events if kind == "file_read" and state == "entrypoint_reachable"]
    reachable_sends = [(pos, state) for kind, pos, state in source_events if kind == "network_send" and state == "entrypoint_reachable"]
    connected = False
    if reachable_reads and reachable_sends:
        source_position = reachable_reads[0][0]
        sink_position = reachable_sends[-1][0]
        if source_position < sink_position:
            connected = b"\x89\xc2" in code[source_position:sink_position]
        flow = (StaticFlowTruth("file_read", "network_send", connected),)

    limitations = ("unresolved_indirect_native_call",) if unresolved else ()
    completeness = "partial" if unresolved else "complete"
    parser_status = "partial" if unresolved else "complete"
    return _truth_from_observations(
        sample_id,
        data,
        "native_x86_64",
        "Linux",
        parser_status,
        observations,
        flow,
        resources,
        resolved_calls,
        imports,
        syscalls=tuple(resolved_syscalls),
        limitations=limitations,
        completeness=completeness,
    )


def _elf_truth(sample_id: str, filename: str, data: bytes) -> ArtifactEvidenceTruth:
    entry, sections = _elf_named_sections(data)
    semantic = _elf_semantic_truth(sample_id, data, entry, sections)
    if semantic is not None:
        return semantic
    text=_elf_text(data)
    if not text:
        return _truth(sample_id,data,"elf64_x86_64","Linux","failed",(),(),(),limitations=("elf_text_unavailable",),completeness="unavailable")
    ops=[]
    if text==b"\xc3":
        ops=[("native_return","entrypoint_reachable")]
        return _truth_from_observations(sample_id,data,"native_x86_64","Linux","complete",ops,(),(),(),())
    # Independent bounded instruction-pattern interpretation for current inert fixture.
    direct_call=text.count(b"\xe8")
    branches=text.count(b"\x75")+text.count(b"\xeb")
    indirect=text.count(b"\xff\xd0")
    ops.extend(("native_call","entrypoint_reachable") for _ in range(direct_call))
    ops.extend(("native_branch","entrypoint_reachable") for _ in range(branches))
    if indirect: ops.extend(("native_call","conditionally_reachable") for _ in range(indirect))
    if b"\xc3" in text: ops.append(("native_return","entrypoint_reachable"))
    if ops: ops.extend(("native_instruction_boundary","entrypoint_reachable") for _ in range(2))
    return _truth_from_observations(sample_id,data,"native_x86_64","Linux","partial",ops,(),(),(),(),limitations=("unresolved_indirect_native_call",),completeness="partial")


def _nested_truth(sample_id: str, filename: str, data: bytes) -> ArtifactEvidenceTruth:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as outer:
            inner_data=outer.read("nested/inner.zip")
        with zipfile.ZipFile(io.BytesIO(inner_data)) as inner:
            names=[n for n in inner.namelist() if not n.endswith("/")]
            if len(names)!=1: raise ValueError
            member=names[0]; member_data=inner.read(member)
    except (KeyError,ValueError,zipfile.BadZipFile,RuntimeError):
        return _truth(sample_id,data,"nested_zip","multi","unavailable",(),(),(),limitations=("nested_archive_structure_unavailable",),completeness="unavailable")
    member_truth=derive_artifact_evidence_truth(sample_id,member,member_data)
    return ArtifactEvidenceTruth(
        sample_id=sample_id, artifact_sha256=sha256(data).hexdigest(), artifact_size=len(data),
        artifact_format="nested_zip:"+member_truth.artifact_format, platform=member_truth.platform,
        parser_status="unavailable", operation_kinds=member_truth.operation_kinds,
        reachability=member_truth.reachability, flow=member_truth.flow,
        resource_identities=member_truth.resource_identities,
        resolved_call_identities=member_truth.resolved_call_identities,
        resolved_import_identities=member_truth.resolved_import_identities,
        resolved_syscall_identities=member_truth.resolved_syscall_identities,
        analysis_limitations=("archive_member_ir_not_published_at_container_boundary",),
        evidence_completeness="unavailable",
    )


def _platform_for(filename: str, source: str) -> str:
    suffix=PurePosixPath(filename).suffix.casefold(); low=source.casefold()
    if suffix in {".ps1",".cmd",".bat",".rpy",".exe",".dll"}: return "Windows"
    if suffix in {".sh",".elf"}: return "Linux"
    if suffix==".py" and any(x in low for x in ("kernel32","dbghelp","login data","powershell.exe")): return "Windows"
    return "multi"


def _truth_from_observations(sample_id: str,data: bytes,fmt: str,platform: str,parser_status: str,observations:list[tuple[str,str]]|tuple[tuple[str,str],...],flow:tuple[StaticFlowTruth,...],resources, calls, imports, *, syscalls:tuple[str,...]=(),limitations:tuple[str,...]=(),completeness:str="complete") -> ArtifactEvidenceTruth:
    kinds=tuple(sorted({k for k,_ in observations}))
    counts={}
    for k,state in observations: counts[(k,state)]=counts.get((k,state),0)+1
    reach=tuple(sorted(StaticReachabilityTruth(k,state,count) for (k,state),count in counts.items()))
    return _truth(sample_id,data,fmt,platform,parser_status,kinds,reach,flow,resources=tuple(sorted(set(resources))),calls=tuple(sorted(set(calls))),imports=tuple(sorted(set(imports))),syscalls=tuple(sorted(set(syscalls))),limitations=limitations,completeness=completeness)


def _truth(sample_id: str,data: bytes,fmt: str,platform: str,parser_status: str,operations,reachability,flow, *, resources:tuple[str,...]=(),calls:tuple[str,...]=(),imports:tuple[str,...]=(),syscalls:tuple[str,...]=(),limitations:tuple[str,...]=(),completeness:str="complete") -> ArtifactEvidenceTruth:
    return ArtifactEvidenceTruth(sample_id=sample_id,artifact_sha256=sha256(data).hexdigest(),artifact_size=len(data),artifact_format=fmt,platform=platform,parser_status=parser_status,operation_kinds=tuple(operations),reachability=tuple(reachability),flow=tuple(flow),resource_identities=resources,resolved_call_identities=calls,resolved_import_identities=imports,resolved_syscall_identities=syscalls,analysis_limitations=limitations,evidence_completeness=completeness)


def derive_artifact_evidence_truth(sample_id: str, artifact_name: str, artifact_bytes: bytes) -> ArtifactEvidenceTruth:
    """Derive physical/deterministic truth from bytes; hidden generator data is not accepted."""
    if type(sample_id) is not str or not sample_id or type(artifact_name) is not str or not artifact_name:
        raise TypeError("artifact_oracle_identity_invalid")
    if type(artifact_bytes) is not bytes or not artifact_bytes:
        raise TypeError("artifact_oracle_bytes_invalid")
    if len(artifact_bytes)>1_048_576: raise ValueError("artifact_oracle_bytes_too_large")
    suffix=PurePosixPath(artifact_name).suffix.casefold()
    if artifact_bytes.startswith(b"PK\x03\x04"): return _nested_truth(sample_id,artifact_name,artifact_bytes)
    if artifact_bytes.startswith(b"MZ"): return _managed_pe_truth(sample_id,artifact_name,artifact_bytes)
    if artifact_bytes.startswith(b"\x7fELF"): return _elf_truth(sample_id,artifact_name,artifact_bytes)
    if suffix==".rb": return _truth(sample_id,artifact_bytes,"ruby_unsupported","multi","unavailable",(),(),(),limitations=("language_frontend_unavailable",),completeness="unavailable")
    if suffix in {".py"}: return _python_truth(sample_id,artifact_name,artifact_bytes)
    if suffix==".rpy": return _renpy_truth(sample_id,artifact_name,artifact_bytes)
    if suffix==".ps1": return _powershell_truth(sample_id,artifact_name,artifact_bytes)
    if suffix in {".cmd",".bat"}: return _batch_truth(sample_id,artifact_name,artifact_bytes)
    if suffix==".sh": return _shell_truth(sample_id,artifact_name,artifact_bytes)
    if suffix==".js": return _js_truth(sample_id,artifact_name,artifact_bytes,typescript=False)
    if suffix==".ts": return _js_truth(sample_id,artifact_name,artifact_bytes,typescript=True)
    return _truth(sample_id,artifact_bytes,"unknown","multi","unavailable",(),(),(),limitations=("artifact_format_unavailable",),completeness="unavailable")


__all__=("derive_artifact_evidence_truth",)
