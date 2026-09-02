"""Public immutable request contracts for raw chunk scanner execution."""

from Virus_Scan.scanners.raw_chunk_collectors import (
    BytecodeChunkRequest,
    ContextualRawChunkRequest,
    bytecode_chunk,
    dotnet_chunk,
    pure_pe_chunk,
)

__all__ = (
    "BytecodeChunkRequest",
    "ContextualRawChunkRequest",
    "bytecode_chunk",
    "dotnet_chunk",
    "pure_pe_chunk",
)
