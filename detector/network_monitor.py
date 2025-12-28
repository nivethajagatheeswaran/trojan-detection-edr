import psutil
import socket

NETWORK_RISK_WEIGHTS = {
    "IMMEDIATE_OUTBOUND_CONNECTION": 20,
    "UNKNOWN_REMOTE_IP": 25,
    "REPEATED_BEACONING": 30
}

def analyze_network_activity(pid):
    
    behavior = {
        "connections": [],
        "suspicious_flags": [],
        "risk_contribution": 0
    }

    try:
        process = psutil.Process(pid)
        connections = process.connections(kind="inet")

        remote_ips = []

        for conn in connections:
            if conn.raddr:
                ip = conn.raddr.ip
                behavior["connections"].append(ip)
                remote_ips.append(ip)

                try:
                    socket.gethostbyaddr(ip)
                except socket.herror:
                    behavior["suspicious_flags"].append("UNKNOWN_REMOTE_IP")
                    behavior["risk_contribution"] += NETWORK_RISK_WEIGHTS["UNKNOWN_REMOTE_IP"]

        if len(remote_ips) >= 3 and len(set(remote_ips)) == 1:
            behavior["suspicious_flags"].append("REPEATED_BEACONING")
            behavior["risk_contribution"] += NETWORK_RISK_WEIGHTS["REPEATED_BEACONING"]

        if remote_ips:
            behavior["suspicious_flags"].append("IMMEDIATE_OUTBOUND_CONNECTION")
            behavior["risk_contribution"] += NETWORK_RISK_WEIGHTS["IMMEDIATE_OUTBOUND_CONNECTION"]

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    return behavior
