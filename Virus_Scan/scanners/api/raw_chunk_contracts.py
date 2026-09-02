"""Public raw-chunk scanner contracts."""
from Virus_Scan.scanners.raw_chunk_collectors import (
    BytecodeChunkRequest,
    ContextualRawChunkRequest,
    bytecode_chunk,
    dotnet_chunk,
    pe_api_chunk,
    pure_pe_chunk,
)
from Virus_Scan.scanners.raw_chunk_core import (
    DEFAULT_GLOBAL_RAW_CONTEXT_ANCHORS,
    DEFAULT_GLOBAL_RAW_DECODE_ANCHORS,
    decoded_chunk_tags,
    read_range_text,
    should_context_scan,
    should_decode_scan,
)
from Virus_Scan.scanners.raw_chunk_engine_collectors import il2cpp_chunk, unity_dotnet_chunk
from Virus_Scan.scanners.raw_chunk_headers import dotnet_header, il2cpp_header, unity_dotnet_header

__all__ = (
    "BytecodeChunkRequest",
    "ContextualRawChunkRequest",
    "DEFAULT_GLOBAL_RAW_CONTEXT_ANCHORS",
    "DEFAULT_GLOBAL_RAW_DECODE_ANCHORS",
    "bytecode_chunk",
    "decoded_chunk_tags",
    "dotnet_chunk",
    "dotnet_header",
    "il2cpp_chunk",
    "il2cpp_header",
    "pe_api_chunk",
    "pure_pe_chunk",
    "read_range_text",
    "should_context_scan",
    "should_decode_scan",
    "unity_dotnet_chunk",
    "unity_dotnet_header",
)
