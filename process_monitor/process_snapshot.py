import psutil

def process_snapshot():
    current_pid = psutil.Process().pid
    proc = psutil.Process(current_pid)

    return {
        "pid": proc.pid,
        "name": proc.name(),
        "exe_path": proc.exe(),
        "parent_name": proc.parent().name() if proc.parent() else None,
        "cmdline": " ".join(proc.cmdline()),
        "is_signed": False,  
        "suspicious_flags": ["SUSPICIOUS_PARENT_PROCESS"]
    }
