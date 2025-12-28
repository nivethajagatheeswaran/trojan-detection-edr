import tkinter as tk
from tkinter import messagebox

def ask_user_action(reason, behavior_summary_text):
    root = tk.Tk()
    root.withdraw()

    choice = messagebox.askquestion(
        title="EDR Decision Required",
        message=(
            "⚠ Suspicious activity detected\n\n"
            f"Reason:\n{reason}\n\n"
            "Observed Behavior:\n"
            f"{behavior_summary_text}\n\n"
            "Do you want to QUARANTINE the detected artifact?"
        ),
        icon="warning"
    )

    if choice == "yes":
        return "QUARANTINE"

    detail_choice = messagebox.askyesno(
        title="EDR Follow-up",
        message="Do you want to view detailed behavior analysis?"
    )

    if detail_choice:
        return "SHOW_DETAILS"

    return "ALLOW"


def show_behavior_popup(title, content):
    root = tk.Tk()
    root.withdraw()

    messagebox.showinfo(
        title=title,
        message=content
    )
