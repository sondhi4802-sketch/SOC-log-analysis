class AdminLoginDetector:

    def detect(self, admin_login_logs):

        alerts = []

        for log in admin_login_logs:

            alerts.append({
                "type": "Admin Login",
                "severity": "Medium",
                "message": "Administrator login detected.",
                "log": log
            })

        return alerts