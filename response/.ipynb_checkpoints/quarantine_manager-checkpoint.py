import shutil
import os
import sys

class QuarantineManager:
    def __init__(self, quarantine_dir=None, allowed_base_dir=None):
        self.quarantine_dir = os.path.abspath(
            quarantine_dir or os.path.join(os.getcwd(), "quarantine")
        )
        self.allowed_base_dir = os.path.abspath(
            allowed_base_dir or os.path.join(os.getcwd(), "simulated_files")
        )

        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(self.allowed_base_dir, exist_ok=True)

    def quarantine_file(self, file_path):
        try:
            if not os.path.exists(file_path):
                return False, f"File does not exist: {file_path}"

            file_path = os.path.abspath(file_path)

            if os.path.normcase(file_path) == os.path.normcase(sys.executable):
                return False, "Blocked: Cannot quarantine the running Python interpreter"

            forbidden_dirs = [
                os.environ.get("SystemRoot", "C:\\Windows"),
                "C:\\Program Files",
                "C:\\Program Files (x86)"
            ]

            for forbidden in forbidden_dirs:
                forbidden = os.path.abspath(forbidden)
                if os.path.commonpath([file_path, forbidden]) == forbidden:
                    return False, f"Blocked: System file detected ({file_path})"

            if os.path.commonpath([file_path, self.allowed_base_dir]) != self.allowed_base_dir:
                return False, f"Blocked: File outside allowed simulation scope ({file_path})"

            base_name = os.path.basename(file_path)
            dest_path = os.path.join(self.quarantine_dir, base_name)
            print("QUARANTINE TARGET:", file_path, "EXISTS:", os.path.exists(file_path))


            counter = 1
            while os.path.exists(dest_path):
                dest_path = os.path.join(
                    self.quarantine_dir, f"{counter}_{base_name}"
                )
                counter += 1

            shutil.move(file_path, dest_path)
            return True, f"Quarantined: {dest_path}"

        except PermissionError:
            return False, f"Permission denied: {file_path}"
        except Exception as e:
            return False, f"Error: {str(e)}"
