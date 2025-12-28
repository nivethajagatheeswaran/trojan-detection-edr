# threat_intelligence/mitre_mapper.py

class MitreMapper:

    EVENT_TO_MITRE = {
        "PROCESS_START": {
            "technique": "T1059",
            "tactic": "Execution",
            "description": "Command and Scripting Interpreter"
        },
        "FILE_DROP_EXECUTABLE": {
            "technique": "T1105",
            "tactic": "Command and Control",
            "description": "Ingress Tool Transfer"
        },
        "PERSISTENCE_ATTEMPT": {
            "technique": "T1547",
            "tactic": "Persistence",
            "description": "Boot or Logon Autostart Execution"
        },
        "NETWORK_BEACONING": {
            "technique": "T1071",
            "tactic": "Command and Control",
            "description": "Application Layer Protocol"
        },
        "REMOTE_COMMAND_EXECUTION": {
            "technique": "T1059",
            "tactic": "Execution",
            "description": "Command Execution"
        },
        "DEFENSE_EVASION": {
            "technique": "T1562",
            "tactic": "Defense Evasion",
            "description": "Impair Defenses"
        }
    }

    def map_event(self, event_type):
        return self.EVENT_TO_MITRE.get(event_type)

    def map_behavior(self, behavior_summary):
        techniques = []

        for event_type in behavior_summary.keys():
            mapping = self.map_event(event_type)
            if mapping:
                techniques.append({
                    "event": event_type,
                    "technique": mapping["technique"],
                    "tactic": mapping["tactic"],
                    "description": mapping["description"]
                })

        return techniques
