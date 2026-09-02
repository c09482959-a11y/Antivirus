from Virus_Scan.reporting.evidence_lines import cli_human_evidence_lines


class HostileOrderedEvents:
    touched = 0

    def __bool__(self):
        HostileOrderedEvents.touched += 1
        raise RuntimeError("ordered_events truthiness must not execute")

    def __iter__(self):
        HostileOrderedEvents.touched += 1
        raise RuntimeError("ordered_events iteration must not execute")

    def __repr__(self):
        HostileOrderedEvents.touched += 1
        raise RuntimeError("ordered_events repr must not execute")

    def __str__(self):
        HostileOrderedEvents.touched += 1
        raise RuntimeError("ordered_events str must not execute")


def test_stage1651_cli_evidence_lines_reject_hostile_ordered_events_without_truthiness():
    HostileOrderedEvents.touched = 0
    result = {
        "tags": ["script_execution"],
        "ordered_events": HostileOrderedEvents(),
        "behavior_timeline": [
            {"tag": "script_execution", "raw": "powershell -enc QUJDREVGR0g="},
        ],
        "score": 50,
    }

    lines = cli_human_evidence_lines("sample.rpy", result)

    assert HostileOrderedEvents.touched == 0
    assert any(line.startswith("Script:") for line in lines)
    assert any("powershell" in line.lower() for line in lines)


def test_stage1651_cli_evidence_lines_preserve_api_ordered_events_fallback_without_or_probe():
    result = {
        "tags": ["cmd_exec"],
        "ordered_events": [],
        "behavior_timeline": [],
        "api": {
            "ordered_events": [
                {"tag": "cmd_exec", "raw": "cmd.exe /c start payload.exe"},
            ],
        },
        "score": 50,
    }

    lines = cli_human_evidence_lines("sample.bat", result)

    assert any(line.startswith("Command:") for line in lines)
    assert any("cmd.exe" in line.lower() for line in lines)
