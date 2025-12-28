import os

FILESYSTEM_RISK_WEIGHTS = {
    "FILE_DROP_EXECUTABLE": 25,
    "PERSISTENCE_ATTEMPT": 35,
    "MODIFY_SYSTEM_DIRECTORY": 30
}

STARTUP_PATHS = [
    "Startup",
    "Run",
    "RunOnce"
]

SYSTEM_DIRECTORIES = [
    "Windows",
    "System32"
]

def analyze_filesystem_activity(exe_path, created_files):

    behavior = {
        "created_files": created_files,
        "suspicious_flags": [],
        "risk_contribution": 0
    }

    for file in created_files:
        lower_file = file.lower()

        if lower_file.endswith(".exe"):
            behavior["suspicious_flags"].append("FILE_DROP_EXECUTABLE")
            behavior["risk_contribution"] += FILESYSTEM_RISK_WEIGHTS["FILE_DROP_EXECUTABLE"]

        for path in STARTUP_PATHS:
            if path.lower() in lower_file:
                behavior["suspicious_flags"].append("PERSISTENCE_ATTEMPT")
                behavior["risk_contribution"] += FILESYSTEM_RISK_WEIGHTS["PERSISTENCE_ATTEMPT"]
                break

        for sys_dir in SYSTEM_DIRECTORIES:
            if sys_dir.lower() in lower_file:
                behavior["suspicious_flags"].append("MODIFY_SYSTEM_DIRECTORY")
                behavior["risk_contribution"] += FILESYSTEM_RISK_WEIGHTS["MODIFY_SYSTEM_DIRECTORY"]
                break

    return behavior
