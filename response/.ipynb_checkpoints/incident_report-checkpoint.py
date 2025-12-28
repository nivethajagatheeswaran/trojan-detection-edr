import json
import time

class IncidentReport:
    def generate(
        self,
        process_info,
        behavior_summary,
        risk_result,
        decision,
        mitre_data=None,          
        timeline=None,
        attack_chain=None
    ):

        classification = self._classify_incident(
            risk_result,
            decision,
            behavior_summary
        )

        report = {
            "timestamp": time.ctime(),
            "process": process_info,
            "behavior_summary": behavior_summary,
            "risk_analysis": risk_result,
            "defense_decision": decision,
            "mitre_techniques": mitre_data or [],   
            "classification": classification        
        }

        if timeline:
            report["timeline"] = timeline

        if attack_chain:
            report["attack_chain"] = attack_chain

        return report

    def save(self, report, filename="incident_report.json"):
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

    def _classify_incident(self, risk_result, decision, behavior_summary):
        score = risk_result.get("risk_score", 0)

        if decision["recommended_action"] == "QUARANTINE":
            if score >= 90:
                return "CONFIRMED TROJAN"
            return "HIGH-RISK MALWARE"

        if decision["recommended_action"] == "USER_DECISION":
            return "SUSPICIOUS ACTIVITY"

        if behavior_summary.get("NETWORK_BEACONING"):
            return "POTENTIAL BACKDOOR"

        return "BENIGN"
