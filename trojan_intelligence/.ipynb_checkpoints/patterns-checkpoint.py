
TROJAN_BEHAVIOR_PATTERNS = [
    {
        "name": "Dropper + Persistence",
        "required_events": {
            "FILE_DROP_EXECUTABLE",
            "PERSISTENCE_ATTEMPT"
        },
        "severity": "HIGH",
        "base_risk": 60
    },
    {
        "name": "Backdoor Establishment",
        "required_events": {
            "NETWORK_BEACONING",
            "PROCESS_START"
        },
        "severity": "HIGH",
        "base_risk": 50,
        "min_counts": {
            "NETWORK_BEACONING": 3
        }

    },
    {
        "name": "Multi-Stage Trojan",
        "required_events": {
            "FILE_DROP_EXECUTABLE",
            "PERSISTENCE_ATTEMPT",
            "NETWORK_BEACONING"
        },
        "severity": "CRITICAL",
        "base_risk": 90
    }
]
