from trojan_intelligence.pattern_matcher import TrojanPatternMatcher

class AnomalyScorer:
    def __init__(self):
        self.matcher = TrojanPatternMatcher()
        self.event_weights = {
            "PROCESS_START": 1,
            "FILE_DROP_EXECUTABLE": 30,
            "PERSISTENCE_ATTEMPT": 40,
            "NETWORK_BEACONING": 20,
            "PRIV_ESCALATION": 50
        }

    def score(self, behavior_summary):
        score = 0
        explanations = []
        event_contributions = []
        SINGLE_EVENT_CAPS = {
            "NETWORK_BEACONING": 40,
            "PROCESS_START": 10,
        }
        for event, count in behavior_summary.items():
            weight = self.event_weights.get(event, 5)
            raw = weight * count
            cap = SINGLE_EVENT_CAPS.get(event)
            if cap is not None:
                raw = min(raw, cap)

            score += raw
            event_contributions.append({
                "event": event,
                "count": count,
                "weight": weight,
                "contribution": raw
            })

        matched_patterns = self.matcher.match(behavior_summary)

        for pattern in matched_patterns:
            score += pattern["base_risk"]
            explanations.append({
                "pattern": pattern["name"],
                "severity": pattern["severity"]
            })

        return {
            "risk_score": min(score, 100),
            "explanations": explanations,
            "event_contributions": event_contributions
        }

