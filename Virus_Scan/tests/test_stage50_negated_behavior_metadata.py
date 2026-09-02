from Virus_Scan.heuristics.game_engine_threats import evaluate_game_engine_threats


def test_negated_malware_family_words_do_not_trigger_detection():
    benign_descriptions = [
        "changelog mentions ransomware movie and miner npc but no code execution",
        "documentation: no ransomware no encryption no miner no network behavior",
        "without rootkit behavior, without adware browser injection, no payload",
        "not a botnet and no ddos command or cnc behavior",
    ]
    danger = {
        "ransomware_behavior", "cryptominer", "wiper_behavior", "rootkit_behavior",
        "adware_behavior", "botnet_behavior", "high_confidence_malware",
    }
    for text in benign_descriptions:
        result = evaluate_game_engine_threats(text, engine="unity", path="Assets/readme.txt")
        tags = set(result.get("tags") or [])
        assert not (tags & danger), (text, sorted(tags & danger), sorted(tags))


def test_affirmed_malware_behavior_still_triggers_after_negation_hardening():
    cases = [
        ("ransomware encrypts files deletes shadow copies vssadmin ransom note", "ransomware_behavior"),
        ("xmrig cryptominer mining pool stratum+tcp high cpu", "cryptominer"),
        ("rootkit kernel driver hides process persistence", "rootkit_behavior"),
        ("adware browser injection downloads payload", "adware_behavior"),
    ]
    for text, required in cases:
        tags = set(evaluate_game_engine_threats(text, engine="unity", path="Assembly-CSharp.cs").get("tags") or [])
        assert required in tags, (text, sorted(tags))
