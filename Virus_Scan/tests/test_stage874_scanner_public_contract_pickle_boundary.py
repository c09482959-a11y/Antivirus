from Virus_Scan.scanners.pickle import scanner

from Virus_Scan.scanners.api import public_contracts


def test_scanner_public_contracts_bootstrap_uses_immutable_module_names():
    module_names = public_contracts.SCANNER_BOOTSTRAP_MODULE_NAMES
    assert isinstance(module_names, tuple)
    assert all(isinstance(module_name, str) for module_name in module_names)
    assert "Virus_Scan.scanners.pickle.scanner" in module_names
    assert "Virus_Scan.scanners.pickle_scan" not in module_names
    assert not hasattr(public_contracts, "SCANNER_BOOTSTRAP_MODULES")


def test_scanner_public_contract_pickle_exports_are_canonical_functions():

    assert public_contracts.detect_python_pickle_opcode_exec is scanner.detect_python_pickle_opcode_exec
    assert public_contracts.pickle_embedded_payload_tags is scanner.pickle_embedded_payload_tags
    assert (
        public_contracts.pickle_fragment_decode_records_from_analysis
        is scanner.pickle_fragment_decode_records_from_analysis
    )
