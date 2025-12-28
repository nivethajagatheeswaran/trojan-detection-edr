class LearningMemory:
    def __init__(self):
        self.override_history = {}

    def record_override(self, process_signature, behavior_summary):
        key = frozenset(behavior_summary.items())

        if key not in self.override_history:
            self.override_history[key] = {
                "count": 0,
                "trusted": False
            }

        self.override_history[key]["count"] += 1

        if self.override_history[key]["count"] >= 3:
            self.override_history[key]["trusted"] = True

    def is_trusted(self, behavior_summary):
        key = frozenset(behavior_summary.items())
        return self.override_history.get(key, {}).get("trusted", False)
