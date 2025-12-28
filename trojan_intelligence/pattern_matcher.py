from trojan_intelligence.patterns import TROJAN_BEHAVIOR_PATTERNS

class TrojanPatternMatcher:
    
    def match(self, behavior_summary):
        matched = []
    
        for pattern in TROJAN_BEHAVIOR_PATTERNS:
            if not all(event in behavior_summary for event in pattern["required_events"]):
                continue
                
            min_counts = pattern.get("min_counts", {})
            violated = False
    
            for event, min_count in min_counts.items():
                if behavior_summary.get(event, 0) < min_count:
                    violated = True
                    break
    
            if violated:
                continue
    
            matched.append(pattern)
    
        return matched
