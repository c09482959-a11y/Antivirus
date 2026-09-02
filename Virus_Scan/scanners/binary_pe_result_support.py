"""PE parse-result normalization support for scanner-owned contracts."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.scanners.binary_pe_evidence import immutable_tag_tuple, mark_pe_helper_error
from Virus_Scan.scanners.contracts.scanner_evidence import freeze_scanner_contract_value


def _pe_result_error_tags(helper_name: str, reason: str) -> tuple[str, ...]:
    return tuple(mark_pe_helper_error(helper_name, ValueError(str.__str__(reason))))


def _combine_error_tags(existing: object, extra: tuple[str, ...]) -> tuple[str, ...]:
    if not extra:
        return immutable_tag_tuple(existing)
    if existing is None:
        existing_items: tuple[object, ...] = ()
    elif type(existing) is tuple:
        existing_items = existing
    elif type(existing) is list:
        existing_items = tuple(existing)
    else:
        existing_items = (existing,)
    return immutable_tag_tuple(existing_items + extra)


def _exact_result_sequence(value: object, *, helper_name: str, rejected_reason: str) -> tuple[tuple[object, ...], tuple[str, ...]]:
    if value is None:
        return (), ()
    if type(value) is tuple:
        return value, ()
    if type(value) is list:
        return tuple(value), ()
    return (), _pe_result_error_tags(helper_name, rejected_reason)


def _freeze_section_records(section_items: tuple[object, ...]) -> tuple[tuple[Mapping[str, object], ...], tuple[str, ...]]:
    frozen_sections: list[Mapping[str, object]] = []
    extra_errors: list[str] = []
    for section in section_items:
        if section is None:
            extra_errors.extend(_pe_result_error_tags("pe_section_result_materialize", "pe_section_record_missing"))
            continue
        if no_hook_mapping_items(section) is None:
            extra_errors.extend(_pe_result_error_tags("pe_section_result_materialize", "pe_section_record_mapping_rejected"))
        frozen_section = freeze_scanner_contract_value(section)
        if isinstance(frozen_section, Mapping):
            frozen_sections.append(frozen_section)
        else:
            frozen_sections.append({"unavailable_reason": "pe_section_record_mapping_rejected"})
    return tuple(frozen_sections), tuple(extra_errors)


@dataclass(frozen=True, slots=True)
class PESectionParseResult:
    sections: tuple[Mapping[str, object], ...] = ()
    error_tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        section_items, section_errors = _exact_result_sequence(
            self.sections,
            helper_name="pe_section_result_materialize",
            rejected_reason="pe_section_result_sequence_rejected",
        )
        frozen_sections, record_errors = _freeze_section_records(section_items)
        object.__setattr__(self, "sections", frozen_sections)
        object.__setattr__(self, "error_tags", _combine_error_tags(self.error_tags, section_errors + record_errors))


def _exact_import_names(names: object) -> tuple[tuple[object, ...], tuple[str, ...]]:
    if names is None:
        return (), ()
    if type(names) is str:
        return (names,), ()
    if type(names) is tuple:
        return names, ()
    if type(names) is list:
        return tuple(names), ()
    return (), _pe_result_error_tags("pe_import_result_materialize", "pe_import_names_sequence_rejected")


def _normalize_import_entry(entry: object) -> tuple[tuple[str, tuple[str, ...]] | None, tuple[str, ...]]:
    if type(entry) not in (tuple, list) or len(entry) != 2:
        return None, _pe_result_error_tags("pe_import_result_materialize", "pe_import_entry_rejected")
    module_value = entry[0]
    names_value = entry[1]
    module, module_reason = no_hook_text(
        module_value,
        missing_reason="pe_import_module_missing",
        unsupported_reason="pe_import_module_rejected",
    )
    errors: list[str] = []
    if module_reason or not module:
        errors.extend(_pe_result_error_tags("pe_import_result_materialize", module_reason or "pe_import_module_empty"))
        return None, tuple(errors)
    name_items, name_errors = _exact_import_names(names_value)
    errors.extend(name_errors)
    normalized_names: list[str] = []
    for name_value in name_items:
        name, name_reason = no_hook_text(
            name_value,
            missing_reason="pe_import_name_missing",
            unsupported_reason="pe_import_name_rejected",
        )
        if name_reason or not name:
            errors.extend(_pe_result_error_tags("pe_import_result_materialize", name_reason or "pe_import_name_empty"))
            continue
        normalized_names.append(name)
    return (module, tuple(normalized_names)), tuple(errors)


def _normalize_import_entries(import_items: tuple[object, ...]) -> tuple[tuple[tuple[str, tuple[str, ...]], ...], tuple[str, ...]]:
    normalized_imports: list[tuple[str, tuple[str, ...]]] = []
    extra_errors: list[str] = []
    for entry in import_items:
        normalized, errors = _normalize_import_entry(entry)
        extra_errors.extend(errors)
        if normalized is not None:
            normalized_imports.append(normalized)
    return tuple(normalized_imports), tuple(extra_errors)


@dataclass(frozen=True, slots=True)
class PEImportParseResult:
    imports: tuple[tuple[str, tuple[str, ...]], ...] = ()
    error_tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        import_items, import_errors = _exact_result_sequence(
            self.imports,
            helper_name="pe_import_result_materialize",
            rejected_reason="pe_import_result_sequence_rejected",
        )
        normalized_imports, entry_errors = _normalize_import_entries(import_items)
        object.__setattr__(self, "imports", normalized_imports)
        object.__setattr__(self, "error_tags", _combine_error_tags(self.error_tags, import_errors + entry_errors))


__all__ = ("PEImportParseResult", "PESectionParseResult")
