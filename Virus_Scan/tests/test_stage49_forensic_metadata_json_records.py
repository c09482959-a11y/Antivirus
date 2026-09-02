from Virus_Scan.heuristics import evaluate_game_engine_threats


def test_malwarebazaar_json_and_python_dict_metadata_records_are_authoritative():
    fixtures = [
        "{'signature': 'RedLine', 'tags': ['stealer'], 'file_type': 'exe'}",
        '{"signature":"Lumma","tags":["stealer","loader"],"file_type":"dll"}',
        '{"vendor_intel":{"classification":"ransomware"},"tags":["ransomware"]}',
        "tag=stealer file_type=exe source=malwarebazaar",
    ]
    for text in fixtures:
        tags = set(evaluate_game_engine_threats(text, engine='unity', path='Assembly-CSharp.dll').get('tags') or [])
        assert 'high_confidence_malware' in tags
        assert 'malware_metadata_category' in tags or 'malwarebazaar_known_family' in tags


def test_malwarebazaar_serialized_clean_metadata_does_not_trigger_without_malicious_terms():
    text = '{"signature":null,"tags":["game","unity","asset"],"file_type":"txt","file_name":"readme.txt"}'
    tags = set(evaluate_game_engine_threats(text, engine='unity', path='readme.txt').get('tags') or [])
    assert 'high_confidence_malware' not in tags
    assert 'malware_metadata_category' not in tags
