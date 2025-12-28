import os

SIMULATED_FILES_DIR = os.path.join(os.getcwd(), "simulated_files")
os.makedirs(SIMULATED_FILES_DIR, exist_ok=True)

def create_dummy_file(filename):
    path = os.path.join(SIMULATED_FILES_DIR, filename)
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write("Safe simulated malware artifact.\n")
    return path

def simulate_behavior(tracker, pid, scenario):

    if scenario == "BENIGN":
        return

    elif scenario == "PERSISTENCE_ONLY":
        tracker.log_event(pid, "PERSISTENCE_ATTEMPT", {})

    elif scenario == "NETWORK_ONLY":
        tracker.log_event(pid, "NETWORK_BEACONING", {})

    elif scenario == "FILE_DROP_ONLY":
        path = create_dummy_file("file_drop_only.exe")
        tracker.log_event(pid, "FILE_DROP_EXECUTABLE", {"path": path})

    elif scenario == "DROP_AND_PERSIST":
        path = create_dummy_file("drop_and_persist.exe")
        tracker.log_event(pid, "FILE_DROP_EXECUTABLE", {"path": path})
        tracker.log_event(pid, "PERSISTENCE_ATTEMPT", {})

    elif scenario == "BACKDOOR_BEHAVIOR":
        tracker.log_event(pid, "NETWORK_BEACONING", {})
        tracker.log_event(pid, "REMOTE_COMMAND_EXECUTION", {})

    elif scenario == "MULTI_STAGE_TROJAN":
        path = create_dummy_file("multi_stage_trojan.exe")
        tracker.log_event(pid, "FILE_DROP_EXECUTABLE", {"path": path})
        tracker.log_event(pid, "PERSISTENCE_ATTEMPT", {})
        tracker.log_event(pid, "NETWORK_BEACONING", {})
        tracker.log_event(pid, "DEFENSE_EVASION", {})

    else:
        raise ValueError(f"Unknown scenario: {scenario}")
