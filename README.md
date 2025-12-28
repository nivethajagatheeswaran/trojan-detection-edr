# **Trojan Detection & Defense Module (EDR Prototype)**

This module is a student-built prototype of an Endpoint Detection and Response (EDR) system designed to monitor process behavior, calculate a risk score, and assist in user-driven security decisions.

## What This Module Does:

- Monitors basic process behaviors (process start, executable file drop)
- Assigns a risk score based on weighted behavioral events
- Generates an incident report with process, behavior, and timeline details
- Uses a human-in-the-loop approach, allowing the user to:
  * Allow the process
  * View technical details
  * Quarantine (when applicable)

## Design Approach:

- Behavior-based detection (not signature-based)
- Console-driven decision flow (no full application or UI)
- Modular structure to support future integration with other security modules

## Architecture

- process_monitor
- ai_engine
- defense
- response
- simulation
- ui
  
## Current Limitations:

- Limited behavior coverage (only a few event types supported)
- No real-time kernel-level monitoring
- Quarantine is simulated and not enforced at OS level
- GUI prompts are basic and not fully integrated with all incident details
- Not suitable for real-world deployment (educational prototype only)

## Future Improvements:

- Add more behavioral indicators (network activity, persistence, injection)
- Improve user decision prompts with richer contextual data
- Integrate with SIEM-style logging and alerting
- Strengthen quarantine and response mechanisms

## Note:

This project is developed for learning and academic purposes to understand how modern EDR systems analyze behavior and involve human decision-making in threat response.
