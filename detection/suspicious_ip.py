import re

class SuspiciousIPDetector:
    def __init__(self):
        pass

    def detect(self, logs):
        alerts = []
        ip_failed_counts = {}
        ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"

        for log in logs:
            upper_log = log.upper()
            
            # Rule 1: Flag IPs associated with explicit threat payloads in logs
            if "SQL INJECTION" in upper_log or "SUSPICIOUS IP" in upper_log:
                match = re.search(ip_pattern, log)
                if match:
                    ip = match.group()
                    alerts.append({
                        "type": "Suspicious IP",
                        "severity": "High",
                        "message": f"Malicious traffic detected from host: {ip}",
                        "log": log
                    })
                    continue

            # Rule 2: Track and flag IPs with high failed logins rate in logs
            if "FAILED LOGIN" in upper_log:
                match = re.search(ip_pattern, log)
                if match:
                    ip = match.group()
                    ip_failed_counts[ip] = ip_failed_counts.get(ip, 0) + 1
                    
                    if ip_failed_counts[ip] >= 5:
                        alerts.append({
                            "type": "Suspicious IP",
                            "severity": "High",
                            "message": f"Host {ip} flagged for multiple authentication failures ({ip_failed_counts[ip]} failed attempts)",
                            "log": log
                        })

        return alerts