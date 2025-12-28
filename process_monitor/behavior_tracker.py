import time
from collections import defaultdict
from datetime import datetime
from threat_intelligence.mitre_mapper import MitreMapper

class BehaviorTracker:
    def __init__(self):
        self.process_behaviors = defaultdict(list)

    def log_event(self, pid, event_type, details=None):
        event = {
            "timestamp": time.time(),
            "event_type": event_type,
            "details": details or {}
        }
        self.process_behaviors[pid].append(event)

    def get_behavior(self, pid):
        return self.process_behaviors.get(pid, [])

    def summarize_behavior(self, pid):
        summary = defaultdict(int)
        for event in self.get_behavior(pid):
            summary[event["event_type"]] += 1
        return dict(summary)

    def get_timeline(self, pid):
        events = self.get_behavior(pid)
        return sorted(events, key=lambda e: e["timestamp"])

    def get_readable_timeline(self, pid):
        timeline = []
        for event in self.get_timeline(pid):
            ts = datetime.fromtimestamp(event["timestamp"]).strftime("%H:%M:%S")
            entry = {
                "time": ts,
                "event": event["event_type"],
                "details": event["details"]
            }
            timeline.append(entry)
        return timeline

    def classify_attack_phase(self, event_type):
        phases = {
            "PROCESS_START": "Initial Execution",
            "FILE_DROP_EXECUTABLE": "Payload Deployment",
            "PERSISTENCE_ATTEMPT": "Persistence",
            "NETWORK_BEACONING": "Command & Control",
            "REMOTE_COMMAND_EXECUTION": "Command Execution",
            "DEFENSE_EVASION": "Defense Evasion"
        }
        return phases.get(event_type, "Unknown")

    def get_attack_chain(self, pid):
        chain = []
        for event in self.get_timeline(pid):
            ts = datetime.fromtimestamp(event["timestamp"]).strftime("%H:%M:%S")
            chain.append({
                "time": ts,
                "event": event["event_type"],
                "phase": self.classify_attack_phase(event["event_type"]),
                "details": event["details"]
            })
        return chain

    def get_mitre_techniques(self, pid):
        mapper = MitreMapper()
        summary = self.summarize_behavior(pid)
        return mapper.map_behavior(summary)
