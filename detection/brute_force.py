class BruteForceDetector:

    def __init__(self):
        self.threshold = 5

    def detect(self, failed_login_logs):

        alerts = []

        if len(failed_login_logs) >= self.threshold:

            alerts.append({
                "type": "Brute Force Attack",
                "severity": "Critical",
                "message": f"{len(failed_login_logs)} failed login attempts detected."
            })

        return alerts