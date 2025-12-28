from process_monitor.process_snapshot import process_snapshot
from process_monitor.behavior_tracker import BehaviorTracker
from ai_engine.anomaly_scorer import AnomalyScorer
from defense.decision_engine import DefenseDecisionEngine
from logging.audit_logger import AuditLogger
from ai_engine.memory import LearningMemory
from response.quarantine_manager import QuarantineManager
from response.incident_report import IncidentReport
from simulation.simulated_trojan import simulate_behavior
from datetime import datetime
import csv
import os
from ui.decision_prompt import ask_user_action

def log_test_result(test_case, behavior, risk, action, expected):
    os.makedirs("logs", exist_ok=True)

    with open("logs/testing_results.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(),
            test_case,
            dict(behavior),
            risk,
            action,
            expected,
            "PASS" if action == expected else "FAIL"
        ])

def find_artifact_path(process_info):
    simulated_dir = "simulated_files"

    for file in os.listdir(simulated_dir):
        full_path = os.path.join(simulated_dir, file)
        if os.path.isfile(full_path):
            return full_path

    return None


def show_full_details(
    process_info,
    behavior_summary,
    risk_result,
    decision,
    timeline,
    attack_chain
):
    print("\n========== FULL INCIDENT DETAILS ==========")

    print("\nProcess Info:")
    for k, v in process_info.items():
        print(f"{k}: {v}")

    print("\nBehavior Summary:")
    for k, v in behavior_summary.items():
        print(f"{k}: {v}")

    print("\nRisk Analysis:")
    print(f"Risk Score: {risk_result['risk_score']}")

    print("\nTimeline:")
    for e in timeline:
        print(f"{e['time']} → {e['event']}")

    print("\nAttack Chain:")
    for e in attack_chain:
        print(f"{e['time']} → {e['event']} ({e['phase']})")

    print("\n==========================================")

def format_behavior_summary(behavior_summary):
    return "\n".join(
        f"- {event}: {count}"
        for event, count in behavior_summary.items()
    )


def handle_user_interaction(
    process_info,
    behavior_summary,
    risk_result,
    decision,
    timeline,
    attack_chain,
    quarantine_manager
):
    print("\n================ EDR DECISION =================")

    system_action = decision["recommended_action"]
    reason = decision["reason"]

    if system_action == "ALLOW":
        print("Process appears safe.")
        print(f"Reason: {reason}")
        return

    if system_action == "USER_DECISION":
        print("Suspicious activity detected.")
        print(f"Reason: {reason}")
    
        behavior_text = format_behavior_summary(behavior_summary)
    
        while True:
            user_action = ask_user_action(reason, behavior_text)
    
            if user_action == "ALLOW":
                print("Process allowed by user decision.")
                return
    
            elif user_action == "SHOW_DETAILS":
                details_text = (
                    "Process Information\n"
                    f"Name: {process_info['name']}\n"
                    f"PID: {process_info['pid']}\n"
                    f"Parent: {process_info['parent_name']}\n\n"
                    "Behavior Summary\n"
                    f"{behavior_text}\n\n"
                    "Risk Score\n"
                    f"{risk_result['risk_score']}"
                )
            
                from ui.decision_prompt import show_behavior_popup
                show_behavior_popup("EDR Behavior Details", details_text)
            
            elif user_action == "QUARANTINE":
                print("Quarantine initiated")
    
                artifact_path = find_artifact_path(process_info)
                if artifact_path:
                    success, msg = quarantine_manager.quarantine_file(artifact_path)
                    print(msg)
                else:
                    print("Quarantine skipped: no artifact available")
    
                return

    if system_action == "QUARANTINE":
        print("Critical threat detected.")
        print(f"Action taken: {reason}")

        artifact_path = find_artifact_path(process_info)
        if artifact_path:
            success, msg = quarantine_manager.quarantine_file(artifact_path)
            print(msg)
        else:
            print("No artifact available to quarantine.")

        cmd = input("\nType 'details' to view full report or press Enter to exit: ")
        if cmd.lower() == "details":
            show_full_details(
                process_info,
                behavior_summary,
                risk_result,
                decision,
                timeline,
                attack_chain
            )

def main():
    tracker = BehaviorTracker()
    quarantine_manager = QuarantineManager()

    process_info = process_snapshot()
    pid = process_info["pid"]

    tracker.log_event(pid, "PROCESS_START", process_info)

    simulate_behavior(tracker, pid, "MULTI_STAGE_TROJAN")

    summary = tracker.summarize_behavior(pid)
    print("Process Info:", process_info)
    print("Behavior Summary:", summary)

    scorer = AnomalyScorer()
    result = scorer.score(summary)
    print("Risk Result:", result)

    dropped_artifact_path = None

    for event in tracker.get_behavior(pid):
        if event["event_type"] == "FILE_DROP_EXECUTABLE":
            dropped_artifact_path = event["details"].get("path")

    process_info["dropped_artifact_path"] = dropped_artifact_path

    engine = DefenseDecisionEngine()
    decision = engine.decide(summary, result)
    print("Defense Decision:", decision)

    log_test_result(
        test_case="MULTI_STAGE_TROJAN Test",
        behavior=summary,
        risk=result["risk_score"],
        action=decision["recommended_action"],
        expected="QUARENTINE"
    )

    mitre_data = (
        tracker.get_mitre_techniques(pid)
        if hasattr(tracker, "get_mitre_techniques")
        else []
    )


    logger = AuditLogger()
    reporter = IncidentReport()

    log_record = {
        "pid": pid,
        "process": process_info["name"],
        "behavior_summary": summary,
        "risk": result,
        "decision": decision
    }
    logger.log(log_record)

    incident = reporter.generate(
        process_info,
        summary,
        result,
        decision,
        mitre_data = mitre_data,
        timeline=tracker.get_readable_timeline(pid),
        attack_chain=tracker.get_attack_chain(pid)
    )

    reporter.save(incident)

    print("Incident report generated")

    handle_user_interaction(
        process_info,
        summary,
        result,
        decision,
        tracker.get_readable_timeline(pid),
        tracker.get_attack_chain(pid),
        quarantine_manager
    )


if __name__ == "__main__":
    main()
