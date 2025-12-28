import sys
import os

class DefenseDecisionEngine:
    def __init__(self, quarantine_threshold=97):
        self.quarantine_threshold = quarantine_threshold

        self.critical_invariants = {
            "CREDENTIAL_THEFT",
            "EXFILTRATION_ATTEMPT",
            "REMOTE_COMMAND_EXECUTION"
        }

        self.patterns_quarantine = [
            {"DEFENSE_EVASION", "NETWORK_BEACONING"},
            {"FILE_DROP_EXECUTABLE", "PERSISTENCE_ATTEMPT", "NETWORK_BEACONING"},
            {"REMOTE_COMMAND_EXECUTION", "NETWORK_BEACONING"}
        ]

    def decide(self, behavior_summary, risk_result, process_info=None):
        risk = risk_result["risk_score"]
        events = set(behavior_summary.keys())

        if process_info:
            exe_path = os.path.abspath(process_info.get("exe_path", ""))
            if exe_path == os.path.abspath(sys.executable):
                return self._response(
                    action="USER_DECISION",
                    reason="Self-protection: runtime interpreter detected",
                    override_allowed=True,
                    quarantine_allowed=False,
                    target_type="PROCESS"
                )

        if events & self.critical_invariants:
            return self._response(
                action="QUARANTINE",
                reason="Critical invariant behavior detected",
                override_allowed=False,
                quarantine_allowed=True,
                target_type="ARTIFACT"
            )

        for pattern in self.patterns_quarantine:
            if pattern <= events:
                return self._response(
                    action="QUARANTINE",
                    reason=f"Critical multi-event pattern detected: {pattern}",
                    override_allowed=False,
                    quarantine_allowed=True,
                    target_type="ARTIFACT"
                )

        if risk < 30:
            return self._response(
                action="ALLOW",
                reason="Behavior within normal baseline",
                override_allowed=False,
                quarantine_allowed=False,
                target_type="PROCESS"
            )

        if 30 <= risk < 60:
            return self._response(
                action="USER_DECISION",
                reason="Suspicious behavior requires user review",
                override_allowed=True,
                quarantine_allowed=False,
                target_type="PROCESS"
            )

        if 60 <= risk < self.quarantine_threshold:
            return self._response(
                action="USER_DECISION",
                reason="High-risk behavior, manual confirmation required",
                override_allowed=True,
                quarantine_allowed=False,
                target_type="PROCESS"
            )

        return self._response(
            action="QUARANTINE",
            reason="Critical threat detected",
            override_allowed=False,
            quarantine_allowed=True,
            target_type="ARTIFACT"
        )

    def _response(self, action, reason, override_allowed, quarantine_allowed, target_type):
        return {
            "recommended_action": action,
            "reason": reason,
            "override_allowed": override_allowed,
            "quarantine_allowed": quarantine_allowed,
            "target_type": target_type
        }
