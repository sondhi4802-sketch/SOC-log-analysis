class SQLInjectionDetector:

    def __init__(self):
        self.keywords = [
            "SQL INJECTION",
            "UNION SELECT",
            "' OR '1'='1",
            "--",
            "DROP TABLE",
            "SELECT * FROM"
        ]

    def detect(self, logs):

        alerts = []

        for log in logs:

            upper_log = log.upper()

            for keyword in self.keywords:

                if keyword.upper() in upper_log:

                    alerts.append({
                        "type": "SQL Injection",
                        "severity": "Critical",
                        "message": "Possible SQL Injection detected.",
                        "log": log
                    })

                    break

        return alerts