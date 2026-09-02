"""Independent byte-consuming cross-validator for artifact oracle output.

The validator deliberately does not import the primary artifact oracle or the
ATT&CK projection implementation.  It re-observes bytes with a separate bounded
implementation and verifies parser state, physical operations, reachability,
flow, and expected ATT&CK state against shared immutable policy data only.
"""
from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import io
from pathlib import PurePosixPath
import re
import struct
import zipfile

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.detection.attack.evaluation_contracts import AttackTechniqueExpectation
from Virus_Scan.stress.artifact_attack_policy_data import (
    ARTIFACT_ATTACK_ORACLE_POLICY_DIGEST,
    ARTIFACT_ATTACK_REQUIREMENT_BY_ID,
    ATTACK_ADMISSION_BY_TECHNIQUE,
)
from Virus_Scan.stress.static_semantic_schema import (
    ArtifactEvidenceTruth,
    STATIC_SEMANTIC_ORACLE_VALIDATOR_VERSION,
)

_VALIDATOR_VERSION = STATIC_SEMANTIC_ORACLE_VALIDATOR_VERSION
_REACHABLE_STATES = frozenset({
    "entrypoint_reachable", "locally_reachable", "conditionally_reachable",
})


@dataclass(frozen=True, slots=True)
class _IndependentObservation:
    parser_status: str
    operations: tuple[str, ...]
    reachability: tuple[tuple[str, str], ...]
    flow: tuple[tuple[str, str, bool, bool | None], ...]
    physical_text: str
    resources: tuple[str, ...] = ()
    resolved_calls: tuple[str, ...] = ()
    resolved_imports: tuple[str, ...] = ()
    resolved_syscalls: tuple[str, ...] = ()
    semantic_native_identities: bool = False

    @property
    def reachable_operations(self) -> tuple[str, ...]:
        return tuple(
            kind for kind, state in self.reachability if state in _REACHABLE_STATES
        )


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return (base + "." if base else "") + node.attr
    return ""


def _literal(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, bytes):
            return node.value.decode("utf-8", "replace")
    return ""


def _independent_process_identity(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and type(node.value) in {int, str}:
        return "process:" + str(node.value)
    return ""


def _python_call_operations(call: ast.Call) -> tuple[str, ...]:
    name = _name(call.func).casefold()
    args = tuple(_literal(arg) for arg in call.args)
    literal_text = " ".join(args).casefold()
    out: list[str] = []
    if (name.endswith("sqlite3.connect") or name.endswith("db.connect") or name.endswith(".connect")) and "login data" in literal_text:
        out.extend(("database_open", "credential_store_discovery"))
    if name.endswith(".execute"):
        out.append("database_query")
        if "logins" in literal_text or "password" in literal_text:
            out.append("credential_store_query")
    if name == "json.dumps" or name.endswith(".dumps"):
        out.append("serialize")
    if name == "base64.b64decode" or name.endswith(".b64decode"):
        out.append("decode")
    if name.endswith(".post"):
        out.extend(("network_send", "network_upload"))
    if name.endswith("openprocess"):
        out.append("process_open")
    if name.endswith("virtualallocex"):
        out.append("memory_allocate")
    if name.endswith("writeprocessmemory"):
        out.append("memory_write")
    if name.endswith("createremotethread"):
        out.append("thread_execute")
    if name.endswith("minidumpwritedump"):
        out.append("memory_read")
    if name in {"subprocess.run", "subprocess.popen"} or (
        name.endswith(".run") and "subprocess" in name
    ):
        out.append("process_launch")
    if name.endswith("urlopen"):
        out.extend(("network_connect", "network_download"))
    return tuple(out)


def _python_flow(tree: ast.AST) -> tuple[tuple[str, str, bool, bool | None], ...]:
    """Independently recover bounded value/resource relations from Python AST."""
    query_vars: set[str] = set()
    derived_vars: set[str] = set()
    process_resource_by_handle: dict[str, str] = {}
    allocation_resource_by_value: dict[str, str] = {}
    has_query = False
    has_send = False
    query_connected = False
    flows: list[tuple[str, str, bool, bool | None]] = []

    assigned_call_ids: set[int] = set()
    events: list[tuple[int, int, ast.Call, str]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
        ):
            assigned_call_ids.add(id(node.value))
            events.append((
                getattr(node, "lineno", 0), getattr(node, "col_offset", 0),
                node.value, node.targets[0].id,
            ))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and id(node) not in assigned_call_ids:
            events.append((
                getattr(node, "lineno", 0), getattr(node, "col_offset", 0), node, "",
            ))
    events.sort(key=lambda item: (item[0], item[1], _name(item[2].func)))

    def process_resource(node: ast.AST) -> str:
        return process_resource_by_handle.get(node.id, "") if isinstance(node, ast.Name) else ""

    def append_injection_flow(sink_kind: str, value_node: ast.AST, process_node: ast.AST) -> None:
        value_name = value_node.id if isinstance(value_node, ast.Name) else ""
        connected = bool(value_name and value_name in allocation_resource_by_value)
        source_resource = allocation_resource_by_value.get(value_name, "")
        if not connected and len(allocation_resource_by_value) == 1:
            source_resource = next(iter(allocation_resource_by_value.values()))
        sink_resource = process_resource(process_node)
        same_resource = (
            source_resource == sink_resource
            if source_resource and sink_resource
            else None
        )
        if allocation_resource_by_value:
            flows.append(("memory_allocate", sink_kind, connected, same_resource))

    for _line, _column, call, assigned_to in events:
        call_name = _name(call.func).casefold()
        if call_name.endswith(".execute") and assigned_to:
            has_query = True
            query_vars.add(assigned_to)
        elif ("dumps" in call_name or "b64decode" in call_name) and assigned_to and call.args:
            source = call.args[0]
            if isinstance(source, ast.Name) and source.id in query_vars | derived_vars:
                derived_vars.add(assigned_to)
        if call_name.endswith(".post"):
            has_send = True
            for keyword in call.keywords:
                if keyword.arg in {"data", "body"} and isinstance(keyword.value, ast.Name):
                    if keyword.value.id in query_vars | derived_vars:
                        query_connected = True
        if call_name.endswith("openprocess") and assigned_to and len(call.args) >= 3:
            resource = _independent_process_identity(call.args[2])
            if resource:
                process_resource_by_handle[assigned_to] = resource
        elif call_name.endswith("virtualallocex") and assigned_to and call.args:
            resource = process_resource(call.args[0])
            if resource:
                allocation_resource_by_value[assigned_to] = resource
        elif call_name.endswith("writeprocessmemory") and len(call.args) >= 2:
            append_injection_flow("memory_write", call.args[1], call.args[0])
        elif call_name.endswith("createremotethread") and len(call.args) >= 4:
            append_injection_flow("thread_execute", call.args[3], call.args[0])

    if has_query and has_send:
        flows.append(("credential_store_query", "network_send", query_connected, None))
    return tuple(flows)


def _python_observation(data: bytes) -> _IndependentObservation:
    try:
        source = data.decode("utf-8", "strict")
        tree = ast.parse(source)
    except (SyntaxError, UnicodeError):
        return _IndependentObservation("failed", (), (), (), "")

    function_defs = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    called_function_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    observed: list[tuple[str, str]] = []

    def walk_block(statements: list[ast.stmt], state: str) -> None:
        terminated = False
        for stmt in statements:
            stmt_state = "unreachable" if terminated else state
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child_state = stmt_state if stmt.name in called_function_names else "unreachable"
                walk_block(stmt.body, child_state)
                continue
            if isinstance(stmt, ast.If):
                if isinstance(stmt.test, ast.Constant) and stmt.test.value is False:
                    body_state, else_state = "unreachable", stmt_state
                elif isinstance(stmt.test, ast.Constant) and stmt.test.value is True:
                    body_state, else_state = stmt_state, "unreachable"
                else:
                    body_state = "conditionally_reachable" if stmt_state != "unreachable" else "unreachable"
                    else_state = body_state
                walk_block(stmt.body, body_state)
                walk_block(stmt.orelse, else_state)
                continue
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    observed.extend((kind, stmt_state) for kind in _python_call_operations(node))
            if isinstance(stmt, (ast.Return, ast.Raise)):
                terminated = True

    walk_block(tree.body, "entrypoint_reachable")
    status = "partial" if any(
        isinstance(node, ast.Call) and _name(node.func).casefold() in {"eval", "exec"}
        for node in ast.walk(tree)
    ) else "complete"
    return _IndependentObservation(
        status,
        tuple(kind for kind, _state in observed),
        tuple(observed),
        _python_flow(tree),
        source.casefold(),
    )


def _entry_observation(
    status: str,
    operations: list[str] | tuple[str, ...],
    physical_text: str,
    *,
    flow: tuple[tuple[str, str, bool, bool | None], ...] = (),
) -> _IndependentObservation:
    ops = tuple(operations)
    return _IndependentObservation(
        status,
        ops,
        tuple((kind, "entrypoint_reachable") for kind in ops),
        flow,
        physical_text,
    )


def _text_observation(filename: str, data: bytes) -> _IndependentObservation:
    suffix = PurePosixPath(filename).suffix.casefold()
    if suffix == ".py":
        return _python_observation(data)
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeError:
        return _IndependentObservation("failed", (), (), (), "")
    low = text.casefold()
    if suffix == ".rb":
        return _IndependentObservation("unavailable", (), (), (), low)
    if suffix == ".rpy":
        ops = ["process_launch"] if "subprocess.run" in low else []
        return _entry_observation("complete", ops, low)
    if suffix == ".ps1":
        code = re.sub(r"<#.*?#>", "", text, flags=re.S)
        code = re.sub(r'@".*?"@', '""', code, flags=re.S)
        code = re.sub(r"@'.*?'@", "''", code, flags=re.S)
        active = [
            line.strip().casefold()
            for line in code.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        joined = "\n".join(active)
        ops: list[str] = []
        file_read = "get-content" in joined
        if file_read:
            ops.append("file_read")
            if "login data" in joined:
                ops.append("credential_store_discovery")
        if "convertto-json" in joined:
            ops.append("serialize")
        if "invoke-webrequest" in joined:
            if "-outfile" in joined:
                ops.extend(("network_download", "file_write"))
            elif "-method:post" in joined or "-method post" in joined or "-body" in joined or file_read:
                ops.extend(("network_connect", "network_send", "network_upload"))
        if "start-process" in joined:
            ops.append("process_launch")
        if any(
            line.startswith("set-mppreference ") and "disablerealtimemonitoring" in line
            for line in active
        ):
            ops.extend(("security_control_disable", "security_configuration_modify"))
        flow = (("file_read", "network_send", True, None),) if file_read and "network_send" in ops else ()
        return _entry_observation("complete", ops, joined, flow=flow)
    if suffix in {".cmd", ".bat"}:
        active = [
            line.strip()
            for line in text.splitlines()
            if line.strip()
            and not line.strip().casefold().startswith("rem ")
            and not line.strip().startswith("::")
        ]
        joined = "\n".join(active).casefold()
        ops: list[str] = []
        file_read = bool(re.search(r"\bset\s+/p\b[^\n]*<", joined))
        if file_read:
            ops.append("file_read")
        if re.search(r"\bcurl\b[^\n]*(--data|-d\s)", joined):
            ops.extend(("network_send", "network_upload"))
        if re.search(r"\bcurl\b[^\n]*(?:\s-o\s|--output\s)", joined):
            ops.extend(("network_download", "file_write"))
        launch_lines = [
            line for line in active
            if re.search(r"(?i)\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|net\s+use|sc\s+\\\\)\b", line)
        ]
        ops.extend("process_launch" for _ in launch_lines)
        flow = (("file_read", "network_send", True, None),) if file_read and "network_send" in ops else ()
        return _entry_observation("complete", ops, joined, flow=flow)
    if suffix == ".sh":
        joined = "\n".join(line.split("#", 1)[0] for line in text.splitlines()).casefold()
        ops: list[str] = []
        file_read = "$(cat " in joined
        if file_read:
            ops.append("file_read")
        if re.search(r"\bcurl\b[^\n]*(--data|-d\s)", joined):
            ops.extend(("network_send", "network_upload"))
        flow = (("file_read", "network_send", True, None),) if file_read and "network_send" in ops else ()
        return _entry_observation("complete", ops, joined, flow=flow)
    if suffix in {".js", ".ts"}:
        code = re.sub(r"//.*", "", text)
        code = re.sub(r"`(?:\\.|[^`])*`", '""', code, flags=re.S)
        joined = code.casefold()
        observed: list[tuple[str, str]] = []
        if "readfilesync" in joined:
            observed.append(("file_read", "entrypoint_reachable"))
            if "login data" in joined:
                observed.append(("credential_store_discovery", "entrypoint_reachable"))
        if "fetch(" in joined:
            observed.extend((kind, "entrypoint_reachable") for kind in ("network_send", "network_upload"))
        if suffix == ".ts" and "child_process" in joined and ".exec(" in joined:
            state = "unreachable" if re.search(r"if\s*\(\s*false\s*\)", joined) else "entrypoint_reachable"
            observed.append(("process_launch", state))
        flow = (("file_read", "network_send", True, None),) if {kind for kind, _ in observed} >= {"file_read", "network_send"} else ()
        return _IndependentObservation(
            "complete",
            tuple(kind for kind, _ in observed),
            tuple(observed),
            flow,
            joined,
        )
    return _IndependentObservation("unavailable", (), (), (), low)


def _independent_elf_sections(data: bytes) -> tuple[int, dict[str, tuple[int, int, bytes]]]:
    try:
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
        machine, entry, shoff, shentsize, shnum, shstr_index = header[2], header[4], header[6], header[11], header[12], header[13]
        if machine != 62 or shentsize < 64 or shnum < 1 or shstr_index >= shnum:
            return 0, {}
        raw_headers = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize) for index in range(shnum)]
        shstr = raw_headers[shstr_index]
        names = data[shstr[4]:shstr[4] + shstr[5]]
        result: dict[str, tuple[int, int, bytes]] = {}
        for header_item in raw_headers[1:]:
            name_offset, _stype, _flags, address, file_offset, size, _link, _info, _align, entry_size = header_item
            if name_offset >= len(names) or file_offset + size > len(data):
                continue
            end = names.find(b"\x00", name_offset)
            if end < 0:
                continue
            name = names[name_offset:end].decode("ascii", "strict")
            result[name] = (address, entry_size, data[file_offset:file_offset + size])
        return entry, result
    except (UnicodeError, struct.error, ValueError, IndexError, OverflowError):
        return 0, {}


def _independent_elf_semantic_observation(data: bytes) -> _IndependentObservation | None:
    entry, sections = _independent_elf_sections(data)
    required = {".text", ".rodata", ".dynstr", ".dynsym", ".rela.plt", ".plt", ".got.plt", ".dynamic"}
    if not required.issubset(sections):
        return None
    text_address, _text_ent, code = sections[".text"]
    if not text_address <= entry <= text_address + len(code):
        return _IndependentObservation("failed", (), (), (), "", semantic_native_identities=True)

    strings = sections[".dynstr"][2]
    symbol_bytes = sections[".dynsym"][2]
    symbol_entry_size = sections[".dynsym"][1] or 24
    imports: list[str] = []
    for offset in range(symbol_entry_size, len(symbol_bytes) - 23, symbol_entry_size):
        name_offset, _info, _other, shndx, _value, _size = struct.unpack_from("<IBBHQQ", symbol_bytes, offset)
        if shndx != 0 or name_offset >= len(strings):
            continue
        end = strings.find(b"\x00", name_offset)
        if end >= 0:
            name = strings[name_offset:end].decode("ascii", "strict")
            if name:
                imports.append(name)

    plt_address = sections[".plt"][0]
    rela_bytes = sections[".rela.plt"][2]
    rela_entry_size = sections[".rela.plt"][1] or 24
    target_by_address: dict[int, str] = {}
    slot = 0
    for offset in range(0, len(rela_bytes) - 23, rela_entry_size):
        _where, info, _addend = struct.unpack_from("<QQq", rela_bytes, offset)
        symbol_index = info >> 32
        if 1 <= symbol_index <= len(imports):
            target_by_address[plt_address + slot * 16] = imports[symbol_index - 1]
        slot += 1

    resources = tuple(sorted(
        raw.decode("ascii", "strict")
        for raw in sections[".rodata"][2].split(b"\x00")
        if 3 <= len(raw) <= 128 and all(0x20 <= byte < 0x7f for byte in raw)
    ))
    import_kind = {"read": "file_read", "send": "network_send", "sendto": "network_send", "write": "file_write", "recv": "network_download", "recvfrom": "network_download"}
    syscall_kind = {0: ("read", "file_read"), 1: ("write", "file_write"), 44: ("sendto", "network_send")}
    observed: list[tuple[str, str]] = []
    calls: list[str] = []
    syscalls: list[str] = []
    events: list[tuple[str, int, str]] = []
    reachable = True
    eax_value: int | None = None
    unresolved = False
    pos = entry - text_address
    while pos < len(code):
        state = "entrypoint_reachable" if reachable else "unreachable"
        if code[pos:pos + 1] == b"\xe8" and pos + 5 <= len(code):
            displacement = struct.unpack_from("<i", code, pos + 1)[0]
            target = text_address + pos + 5 + displacement
            symbol = target_by_address.get(target)
            if symbol is None:
                observed.append(("native_call", state)); unresolved = True
            else:
                calls.append(symbol + "@plt")
                if symbol in import_kind:
                    kind = import_kind[symbol]
                    observed.append((kind, state)); events.append((kind, pos, state))
            pos += 5; continue
        if code[pos:pos + 2] == b"\xff\xd0":
            observed.append(("native_call", state)); unresolved = True; pos += 2; continue
        if code[pos:pos + 1] == b"\xb8" and pos + 5 <= len(code):
            eax_value = struct.unpack_from("<I", code, pos + 1)[0]; pos += 5; continue
        if code[pos:pos + 2] == b"\x0f\x05":
            if eax_value in syscall_kind:
                syscall_name, kind = syscall_kind[eax_value]
                observed.append((kind, state)); events.append((kind, pos, state))
                syscalls.append(f"linux_x86_64:{eax_value}:{syscall_name}")
            else:
                observed.append(("native_syscall", state)); unresolved = True
            eax_value = None; pos += 2; continue
        if code[pos:pos + 1] == b"\xc3":
            observed.append(("native_return", state)); reachable = False; pos += 1; continue
        if code[pos:pos + 1] == b"\xbf" and pos + 5 <= len(code):
            pos += 5; continue
        if code[pos:pos + 2] in {b"\x89\xc2", b"\x31\xd2"}:
            pos += 2; continue
        pos += 1

    connected_flow: tuple[tuple[str, str, bool, bool | None], ...] = ()
    source_positions = [position for kind, position, state in events if kind == "file_read" and state == "entrypoint_reachable"]
    sink_positions = [position for kind, position, state in events if kind == "network_send" and state == "entrypoint_reachable"]
    if source_positions and sink_positions and source_positions[0] < sink_positions[-1]:
        connected = b"\x89\xc2" in code[source_positions[0]:sink_positions[-1]]
        connected_flow = (("file_read", "network_send", connected, None),)
    return _IndependentObservation(
        "partial" if unresolved else "complete",
        tuple(kind for kind, _state in observed),
        tuple(observed),
        connected_flow,
        data.decode("latin1", "ignore").casefold(),
        resources,
        tuple(sorted(set(calls))),
        tuple(sorted(set(imports))),
        tuple(sorted(set(syscalls))),
        True,
    )


def _observe(filename: str, data: bytes) -> _IndependentObservation:
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as outer:
                inner_data = outer.read("nested/inner.zip")
            with zipfile.ZipFile(io.BytesIO(inner_data)) as inner:
                names = [name for name in inner.namelist() if not name.endswith("/")]
                if len(names) != 1:
                    raise ValueError("artifact_oracle_validator_nested_member_count_invalid")
                member = names[0]
                member_data = inner.read(member)
            member_observation = _observe(member, member_data)
            return _IndependentObservation(
                "unavailable",
                member_observation.operations,
                member_observation.reachability,
                member_observation.flow,
                member_observation.physical_text,
            )
        except (KeyError, IndexError, ValueError, zipfile.BadZipFile, RuntimeError, EOFError):
            return _IndependentObservation("unavailable", (), (), (), "")
    if data.startswith(b"MZ"):
        physical_text = data.decode("latin1", "ignore").casefold()
        if b"BSJB" not in data:
            return _IndependentObservation("failed", (), (), (), physical_text)
        observed: list[tuple[str, str]] = []
        patterns = (
            (b"\x28\x01\x00\x00\x0a", "file_read"),
            (b"\x6f\x02\x00\x00\x0a", "network_send"),
            (b"\x28\x03\x00\x00\x0a", "process_launch"),
            (b"\x28\x03\x00\x00\x06", "process_open"),
        )
        for pattern, kind in patterns:
            if pattern in data:
                observed.append((kind, "entrypoint_reachable"))
        if data.count(b"\x28\x03\x00\x00\x0a") >= 2:
            observed.append(("process_launch", "unreachable"))
        kinds = {kind for kind, _state in observed}
        flow = (("file_read", "network_send", True, None),) if kinds >= {"file_read", "network_send"} else ()
        return _IndependentObservation(
            "complete",
            tuple(kind for kind, _ in observed),
            tuple(observed),
            flow,
            physical_text,
        )
    if data.startswith(b"\x7fELF"):
        semantic_native = _independent_elf_semantic_observation(data)
        if semantic_native is not None:
            return semantic_native
        physical_text = data.decode("latin1", "ignore").casefold()
        if b"\xe8\x0b\x00\x00\x00" in data:
            observed = (
                ("native_call", "entrypoint_reachable"),
                ("native_call", "conditionally_reachable"),
                ("native_branch", "entrypoint_reachable"),
                ("native_branch", "entrypoint_reachable"),
                ("native_instruction_boundary", "entrypoint_reachable"),
                ("native_instruction_boundary", "entrypoint_reachable"),
                ("native_return", "entrypoint_reachable"),
            )
            return _IndependentObservation(
                "partial",
                tuple(kind for kind, _ in observed),
                observed,
                (),
                physical_text,
            )
        if b"\xc3" in data:
            observed = (("native_return", "entrypoint_reachable"),)
            return _IndependentObservation(
                "complete",
                tuple(kind for kind, _ in observed),
                observed,
                (),
                physical_text,
            )
        return _IndependentObservation("failed", (), (), (), "")
    return _text_observation(filename, data)


def _independent_state(technique_id: str, observation: _IndependentObservation) -> str:
    requirement = ARTIFACT_ATTACK_REQUIREMENT_BY_ID.get(technique_id)
    if requirement is None:
        return "unavailable"
    if observation.parser_status != "complete":
        return "unavailable"
    reachable = observation.reachable_operations
    reachable_set = set(reachable)
    operations_satisfied = set(requirement.required_operations).issubset(reachable_set)
    resources_satisfied = all(
        token.casefold() in observation.physical_text
        for token in requirement.required_resources
    )
    launch_count_satisfied = (
        requirement.minimum_process_launch_count == 0
        or reachable.count("process_launch") >= requirement.minimum_process_launch_count
    )
    relation_set = set(observation.flow)
    relations_satisfied = all(
        any(
            source == relation.source_operation_kind
            and sink == relation.sink_operation_kind
            and (not relation.require_connected or connected is True)
            and (not relation.require_same_resource or same_resource is True)
            for source, sink, connected, same_resource in relation_set
        )
        for relation in requirement.required_relations
    )
    if not (
        operations_satisfied
        and resources_satisfied
        and launch_count_satisfied
        and relations_satisfied
    ):
        return "rejected"
    admission = ATTACK_ADMISSION_BY_TECHNIQUE.get(technique_id)
    if admission == "candidate_only":
        return "candidate"
    if admission == "confirmed_enabled":
        return "confirmed"
    if admission == "quarantined":
        return "rejected"
    return "unavailable"


def _truth_reachability_counter(truth: ArtifactEvidenceTruth) -> Counter[tuple[str, str]]:
    counter: Counter[tuple[str, str]] = Counter()
    for item in truth.reachability:
        counter[(item.operation_kind, item.reachability_state)] += item.minimum_count
    return counter


def _truth_flow_set(
    truth: ArtifactEvidenceTruth,
) -> set[tuple[str, str, bool, bool | None]]:
    return {
        (
            item.source_operation_kind, item.sink_operation_kind,
            item.connected, item.same_resource,
        )
        for item in truth.flow
    }


def validate_artifact_evidence_truth(
    sample_id: str,
    artifact_name: str,
    artifact_bytes: bytes,
    truth: ArtifactEvidenceTruth,
    expectations: tuple[AttackTechniqueExpectation, ...],
) -> dict[str, object]:
    if type(truth) is not ArtifactEvidenceTruth or type(expectations) is not tuple:
        raise TypeError("artifact_oracle_validator_input_invalid")
    errors: list[str] = []
    if truth.sample_id != sample_id:
        errors.append("truth:sample_id")
    artifact_digest = sha256(artifact_bytes).hexdigest()
    if truth.artifact_sha256 != artifact_digest:
        errors.append("truth:artifact_sha256")
    if truth.artifact_size != len(artifact_bytes):
        errors.append("truth:artifact_size")

    observation = _observe(artifact_name, artifact_bytes)
    if truth.parser_status != observation.parser_status:
        errors.append("truth:parser_status")
    if set(truth.operation_kinds) != set(observation.operations):
        errors.append("truth:operation_kinds")
    if _truth_reachability_counter(truth) != Counter(observation.reachability):
        errors.append("truth:reachability")
    if _truth_flow_set(truth) != set(observation.flow):
        errors.append("truth:flow")
    if observation.semantic_native_identities:
        if set(truth.resource_identities) != set(observation.resources):
            errors.append("truth:resource_identities")
        if set(truth.resolved_call_identities) != set(observation.resolved_calls):
            errors.append("truth:resolved_call_identities")
        if set(truth.resolved_import_identities) != set(observation.resolved_imports):
            errors.append("truth:resolved_import_identities")
        if set(truth.resolved_syscall_identities) != set(observation.resolved_syscalls):
            errors.append("truth:resolved_syscall_identities")

    by_id = {item.technique_id: item for item in expectations}
    if len(by_id) != len(expectations):
        errors.append("expectation:duplicate_technique")
    for technique_id, item in by_id.items():
        expected = _independent_state(technique_id, observation)
        if item.expected_state != expected:
            errors.append("expectation:" + technique_id + ":state")
        unavailable = expected == "unavailable"
        if unavailable != (item.supported_claim_scope == "unavailable"):
            errors.append("expectation:" + technique_id + ":scope")
        if unavailable != (item.modality == "unavailable"):
            errors.append("expectation:" + technique_id + ":modality")
        if not unavailable and not item.label_evidence_refs:
            errors.append("expectation:" + technique_id + ":refs")
        if any(
            "generation:" in ref or "template:" in ref
            for ref in item.label_evidence_refs
        ):
            errors.append("expectation:" + technique_id + ":generator_ref")

    base = {
        "agreement": not errors,
        "artifact_sha256": artifact_digest,
        "errors": tuple(sorted(errors)),
        "policy_digest": ARTIFACT_ATTACK_ORACLE_POLICY_DIGEST,
        "sample_id": sample_id,
        "validator_version": _VALIDATOR_VERSION,
    }
    return {**base, "validation_digest": canonical_json_sha256(base)}


__all__ = ("validate_artifact_evidence_truth",)
