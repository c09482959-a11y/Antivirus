"""Scanner-owned text extraction and normalization helpers.

Phase 11 keeps payload decoding and AST string extraction in a bounded text
module so ``text.py`` no longer mixes extraction, API graphing, raw chunks, and
validation policy ownership.
"""

import ast
import re

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import DECODE_LAYER_MAX_DEPTH
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.contracts.string_eval import const_eval_string_node
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scanners.payload_decode import safe_decode_payloads
from Virus_Scan.utils.text_validation import tag_validation_text as _canonical_tag_validation_text
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items, no_hook_text, no_hook_type_name


def _safe_cli_text(value: object) -> object:
    """Return text that is safe for the active Windows/terminal encoding."""
    text, reason = no_hook_text(
        value,
        missing_reason="missing_scanner_cli_text",
        unsupported_reason="unsafe_scanner_cli_text_rejected",
    )
    if reason:
        return "<" + no_hook_type_name(value) + ">"
    text = re.sub('[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f-\\x9f]+', ' ', text)
    return text.encode('utf-8', errors='backslashreplace').decode('utf-8', errors='replace')


def _tag_validation_text(strings_blob: object = '') -> object:
    """Return normalized scanner validation text from the canonical text-validation contract."""
    return _canonical_tag_validation_text(strings_blob)


def _umige_ast_enriched_strings(code: object, max_items: object = 256) -> object:
    """Extract literal and trivially-folded strings from Python/Ren'Py source."""
    out = []
    source, source_reason = no_hook_text(
        code,
        missing_reason="missing_scanner_ast_source",
        unsupported_reason="unsafe_scanner_ast_source_rejected",
    )
    if source_reason:
        return out
    try:
        tree = ast.parse(source)
    except SCAN_CONTENT_ERRORS:
        return out
    env = {}
    try:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                val = const_eval_string_node(node.value, env)
                if isinstance(val, str) and len(val) <= 16384:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            env[target.id] = val
            elif isinstance(node, ast.AnnAssign):
                val = const_eval_string_node(node.value, env) if node.value is not None else None
                if isinstance(val, str) and isinstance(node.target, ast.Name) and (len(val) <= 16384):
                    env[node.target.id] = val
    except SCAN_CONTENT_ERRORS as _umige_exc:
        record_suppressed_failure('suppressed_exception', _umige_exc, domain='runtime')
    try:
        for node in ast.walk(tree):
            val = const_eval_string_node(node, env)
            if isinstance(val, str) and val and (len(val) <= 65536):
                out.append(val)
                if len(out) >= max_items:
                    break
    except SCAN_CONTENT_ERRORS as _umige_exc:
        record_suppressed_failure('suppressed_exception', _umige_exc, domain='runtime')
    try:
        for _name, val in no_hook_mapping_items(env) or ():
            if val and val not in out:
                out.append(val)
                if len(out) >= max_items:
                    break
    except SCAN_CONTENT_ERRORS as _umige_exc:
        record_suppressed_failure('suppressed_exception', _umige_exc, domain='runtime')
    return out


def _scanner_latin1_text(value: object, *, missing_reason: object = "missing_scanner_text", unsupported_reason: object = "unsafe_scanner_text_rejected") -> object:
    if type(value) is bytes:
        return bytes(value).decode('latin1', errors='ignore'), ''
    if type(value) is bytearray:
        return bytes(value).decode('latin1', errors='ignore'), ''
    return no_hook_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)


def _scanner_mapping_get(mapping: object, key: object, default: object = '') -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and str.__str__(item_key) == key:
            return item_value
    return default


def _scanner_decode_records(raw: object, limit: object) -> object:
    return no_hook_sequence_items(safe_decode_payloads(raw, max_depth=DECODE_LAYER_MAX_DEPTH))[:limit]


def _umige_build_extraction_view(strings_blob: object, path: object = None) -> object:
    """Build bounded raw + normalized + AST + decoded view for scanning."""
    raw, raw_reason = _scanner_latin1_text(
        strings_blob,
        missing_reason="missing_scanner_extraction_text",
        unsupported_reason="unsafe_scanner_extraction_text_rejected",
    )
    if raw_reason:
        raw = ''
    parts = [raw, _umige_normalize_obfuscated_text(raw)]
    try:
        ext = get_scan_extension(path) if path is not None else ''
    except SCAN_CONTENT_ERRORS:
        ext = '.scanner_ext_error'
    if ext in {'.py', '.pyw', '.rpy', '.rpyw', '.js', '.txt'} or len(raw) <= 2000000:
        try:
            ast_strings = _umige_ast_enriched_strings(raw)
            if ast_strings:
                joined = '\n'.join(ast_strings[:256])
                parts.append(joined)
                parts.append(_umige_normalize_obfuscated_text(joined))
        except SCAN_CONTENT_ERRORS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except SCAN_CONTENT_ERRORS as _umige_reporting_exc:
                _ = _umige_reporting_exc
    try:
        for rec in _scanner_decode_records(raw, 16):
            txt = _scanner_mapping_get(rec, 'text', '')
            if txt:
                sample = txt[:65536]
                parts.append(sample)
                parts.append(_umige_normalize_obfuscated_text(sample))
    except SCAN_CONTENT_ERRORS as _umige_exc:
        record_suppressed_failure('suppressed_exception', _umige_exc, domain='runtime')
    return '\n'.join((p for p in parts if p))[:4000000]


def _umige_normalize_obfuscated_text(blob: object) -> object:
    """Return a lower-case matching view robust to trivial string obfuscation."""
    text, text_reason = _scanner_latin1_text(
        blob,
        missing_reason="missing_scanner_obfuscated_text",
        unsupported_reason="unsafe_scanner_obfuscated_text_rejected",
    )
    if text_reason:
        text = ''
    try:
        qlit = '([\'\\"])([A-Za-z0-9_\\-/.\\\\:]+)\\1'
        pat = re.compile(qlit + '\\s*\\+\\s*' + qlit)
        prev = None
        while prev != text:
            prev = text
            text = pat.sub(lambda m: repr((m.group(2) or '') + (m.group(4) or '')), text)
        pat2 = re.compile(qlit + '\\s+' + qlit)
        prev = None
        while prev != text:
            prev = text
            text = pat2.sub(lambda m: repr((m.group(2) or '') + (m.group(4) or '')), text)
    except SCAN_CONTENT_ERRORS as _umige_exc:
        record_suppressed_failure('suppressed_exception', _umige_exc, domain='runtime')
    low = text.lower()
    try:
        low = low.replace('`', '').replace('\x00', '')
        low = re.sub('p\\s*o\\s*w\\s*e\\s*r\\s*s\\s*h\\s*e\\s*l\\s*l', 'powershell', low)
        low = re.sub('p\\s*w\\s*s\\s*h', 'pwsh', low)
        low = re.sub('-\\s*e\\s*n\\s*c(?:\\s*o\\s*d\\s*e\\s*d\\s*c\\s*o\\s*m\\s*m\\s*a\\s*n\\s*d)?', '-enc', low)
        low = re.sub('b\\s*a\\s*s\\s*e\\s*6\\s*4', 'base64', low)
        low = re.sub('s\\s*o\\s*c\\s*k\\s*e\\s*t\\s*\\.\\s*c\\s*r\\s*e\\s*a\\s*t\\s*e\\s*_?\\s*c\\s*o\\s*n\\s*n\\s*e\\s*c\\s*t\\s*i\\s*o\\s*n', 'socket.create_connection', low)
        low = re.sub('\\s+', ' ', low)
    except SCAN_CONTENT_ERRORS as _umige_exc:
        record_suppressed_failure('suppressed_exception', _umige_exc, domain='runtime')
    return low


__all__ = (
    '_safe_cli_text',
    '_tag_validation_text',
    '_umige_ast_enriched_strings',
    '_umige_build_extraction_view',
    '_umige_normalize_obfuscated_text',
)
