import json
import time
import os

class AuditLogger:
    def __init__(self, log_file="audit_log.json"):
        self.log_file = log_file

        if not os.path.exists(self.log_file):
            with open(self.log_file, "w") as f:
                json.dump([], f)

    def log(self, record):
        record["timestamp"] = time.time()

        with open(self.log_file, "r+") as f:
            data = json.load(f)
            data.append(record)
            f.seek(0)
            json.dump(data, f, indent=2)
