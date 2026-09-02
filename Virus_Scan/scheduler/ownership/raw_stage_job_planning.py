"""Raw-stage job workload classification and publication planning."""
from __future__ import annotations

from dataclasses import dataclass
import os

from Virus_Scan.contracts.env_config import bool_env, int_env
from Virus_Scan.scheduler.ownership.raw_stage_job_admission import RawStageJobAdmissionState
from Virus_Scan.yara.execution_policy import (
    selected_yara_snapshot,
    selected_yara_snapshot_ready,
    yara_light_selected,
)


@dataclass(frozen=True)
class RawStageFileShape:
    size: int
    ext: str
    is_pe: bool
    maybe_dotnet: bool
    maybe_unity: bool
    maybe_il2cpp: bool
    is_runtime_ext: bool


def probe_raw_stage_file(path: object, *, deps: object) -> RawStageFileShape:
    try:
        size = os.path.getsize(path)
    except OSError as size_exc:
        deps.record_suppressed("raw_build_jobs_file_size_failed", size_exc)
        size = 0
    ext = deps.get_scan_extension(path)
    try:
        with open(path, "rb") as file_handle:
            head = file_handle.read(262144)
    except OSError as read_exc:
        deps.record_suppressed("raw_build_jobs_file_probe_failed", read_exc)
        head = b""
    head_l = head.lower()
    is_pe = head.startswith(b"MZ") or ext in {".exe", ".dll", ".sys", ".ocx"}
    maybe_dotnet = is_pe and (
        b"mscoree.dll" in head_l
        or b"_cor_exe_main" in head_l
        or b"_cor_dll_main" in head_l
        or b"#strings" in head_l
        or b"#us" in head_l
        or b"#blob" in head_l
    )
    maybe_unity = is_pe and (b"assembly-csharp" in head_l or b"unityengine" in head_l or b"monobehaviour" in head_l)
    maybe_il2cpp = is_pe and (b"il2cpp" in head_l or b"global-metadata.dat" in head_l)
    is_runtime_ext = ext in {
        ".py",
        ".pyc",
        ".pyo",
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".jar",
        ".class",
        ".rpy",
        ".rpyc",
        ".rpyb",
    }
    return RawStageFileShape(
        size=size,
        ext=ext,
        is_pe=is_pe,
        maybe_dotnet=maybe_dotnet,
        maybe_unity=maybe_unity,
        maybe_il2cpp=maybe_il2cpp,
        is_runtime_ext=is_runtime_ext,
    )


def add_raw_stage_chunk_jobs(state: RawStageJobAdmissionState, *, shape: RawStageFileShape, effective_stage: str, deps: object) -> None:
    chunk = max(16384, deps.raw_chunk_bytes())
    max_chunks = max(1, deps.raw_queue_max_chunks())
    if shape.size <= 0:
        return
    step_count = min(max_chunks, max(1, (shape.size + chunk - 1) // chunk))
    if step_count >= max_chunks:
        chunk = max(chunk, (shape.size + step_count - 1) // step_count)
    for start in range(0, min(shape.size, chunk * step_count), chunk):
        read_size = min(chunk + 2048, max(0, shape.size - start))
        state.add("binary_context", start, read_size)
        state.add("decode", start, read_size)
        if effective_stage in {"binary", "runtime", "other", "unknown"}:
            state.add("payload", start, read_size)
        add_raw_stage_pe_chunk_jobs(state, shape=shape, start=start, read_size=read_size)
        if effective_stage == "runtime" or shape.is_runtime_ext:
            state.add("bytecode_chunk", start, read_size)
        if shape.ext in {".rpy", ".rpyc", ".rpyb"}:
            state.add("renpy_chunk", start, read_size)
        if shape.ext == ".js":
            state.add("rpgm_js_ast_chunk", start, read_size)
            state.add("js_exec", start, read_size)


def add_raw_stage_pe_chunk_jobs(state: RawStageJobAdmissionState, *, shape: RawStageFileShape, start: int, read_size: int) -> None:
    if not shape.is_pe:
        return
    state.add("pure_pe_chunk", start, read_size)
    state.add("pe_api_chunk", start, read_size)
    if shape.maybe_dotnet:
        state.add("dotnet_chunk", start, read_size)
    if shape.maybe_unity:
        state.add("unity_dotnet_chunk", start, read_size)
    if shape.maybe_il2cpp:
        state.add("il2cpp_chunk", start, read_size)


def add_raw_stage_file_jobs(state: RawStageJobAdmissionState, *, shape: RawStageFileShape, effective_stage: str) -> None:
    if shape.is_pe:
        state.add("pe_api")
        state.add("pure_pe")
        if shape.maybe_dotnet:
            state.add("dotnet")
        if shape.maybe_unity:
            state.add("unity_dotnet")
        if shape.maybe_il2cpp:
            state.add("il2cpp")
    if effective_stage == "runtime" or shape.is_runtime_ext:
        state.add("bytecode")
        if shape.ext in {".rpy", ".rpyc", ".rpyb"}:
            state.add("renpy")
        if shape.ext in {".rvdata", ".rvdata2", ".rxdata"}:
            state.add("rpgm")
        if shape.ext == ".js":
            state.add("rpgm_js_ast")


def add_raw_stage_yara_jobs(state: RawStageJobAdmissionState, *, deps: object) -> None:
    if bool_env("UMIGE_NO_YARA", False):
        return
    try:
        state_owner = deps.yara_rules_state()
        selected = selected_yara_snapshot(state_owner)
        if not selected_yara_snapshot_ready(selected):
            return
        if yara_light_selected():
            state.add("yara")
            return
    except (OSError, TypeError, ValueError, RuntimeError) as error:
        deps.record_suppressed("raw_yara_selected_snapshot_unavailable", error)
        return
    state.add("yara")


def apply_raw_stage_job_cap(jobs: list[dict[str, object]], *, ext: str, deps: object) -> list[dict[str, object]]:
    try:
        raw_cap = min(int(deps.runtime_value("RAW_PER_FILE_ACTIVE_CAP", 128) or 128), 64)
        ext_cap = int_env("UMIGE_RAW_MAX_JOBS_PER_FILE", raw_cap, 1, None)
    except (TypeError, ValueError, RuntimeError):
        ext_cap = 64
    try:
        if ext in {".dll", ".exe", ".sys", ".ocx"} and not deps.deep_scan_thorough():
            ext_cap = min(ext_cap, int_env("UMIGE_RAW_PE_MAX_JOBS_PER_FILE", 48, 1, None))
    except (TypeError, ValueError, RuntimeError) as exc:
        deps.record_suppressed("raw_build_jobs_deep_scan_cap_failed", exc)
    if ext_cap > 0 and len(jobs) > ext_cap:
        return jobs[:ext_cap]
    return jobs
