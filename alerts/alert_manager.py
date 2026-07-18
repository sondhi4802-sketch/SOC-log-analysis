import os


class AlertManager:

    def __init__(self):

        self.alert_file = "alerts/alerts.txt"

        # Create alerts.txt if it doesn't exist
        if not os.path.exists(self.alert_file):
            with open(self.alert_file, "w") as file:
                pass

    # ----------------------------
    # Save Alert
    # ----------------------------
    def save_alert(self, alert):

        with open(self.alert_file, "a") as file:
            file.write(alert + "\n")

    # ----------------------------
    # Read All Alerts
    # ----------------------------
    def get_alerts(self):

        with open(self.alert_file, "r") as file:
            alerts = file.readlines()

        return [alert.strip() for alert in alerts if alert.strip()]

    # ----------------------------
    # Count Alerts
    # ----------------------------
    def total_alerts(self):

        return len(self.get_alerts())

    # ----------------------------
    # Clear All Alerts
    # ----------------------------
    def clear_alerts(self):

        with open(self.alert_file, "w") as file:
            pass

    # ----------------------------
    # Search Alerts
    # ----------------------------
    def search_alerts(self, keyword):

        keyword = keyword.lower()

        return [
            alert
            for alert in self.get_alerts()
            if keyword in alert.lower()
        ]

    # ----------------------------
    # Filter Alerts
    # ----------------------------
    def filter_alerts(self, severity):

        severity = severity.lower()

        return [
            alert
            for alert in self.get_alerts()
            if severity in alert.lower()
        ]