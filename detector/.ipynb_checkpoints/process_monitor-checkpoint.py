import psutil
import os

PROCESS_RISK_WEIGHTS = {
    "EXECUTION_FROM_USER_WRITABLE_PATH": 20,
    "SUSPICIOUS_PARENT_PROCESS": 15,
    "SUSPICIOUS_COMMAND_LINE": 25
}

def monitor_process(pid):

    try:
        process = psutil.Process(pid)

        process_info = {
            "pid": pid,
            "name": process.name(),
            "exe_path": process.exe(),
            "parent_name": process.parent().name() if process.parent() else None,
            "cmdline": " ".join(process.cmdline()),
            "suspicious_flags": [],
            "risk_contribution": 0
        }

        if "Downloads" in process_info["exe_path"] or "Temp" in process_info["exe_path"]:
            flag = "EXECUTION_FROM_USER_WRITABLE_PATH"
            process_info["suspicious_flags"].append(flag)
            process_info["risk_contribution"] += PROCESS_RISK_WEIGHTS[flag]

        suspicious_parents = ["powershell.exe", "cmd.exe", "wscript.exe"]
        if process_info["parent_name"] and process_info["parent_name"].lower() in suspicious_parents:
            flag = "SUSPICIOUS_PARENT_PROCESS"
            process_info["suspicious_flags"].append(flag)
            process_info["risk_contribution"] += PROCESS_RISK_WEIGHTS[flag]

        suspicious_cmd_keywords = ["-enc", "bypass", "hidden"]
        for keyword in suspicious_cmd_keywords:
            if keyword in process_info["cmdline"].lower():
                flag = "SUSPICIOUS_COMMAND_LINE"
                process_info["suspicious_flags"].append(flag)
                process_info["risk_contribution"] += PROCESS_RISK_WEIGHTS[flag]
                break

        return process_info

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
