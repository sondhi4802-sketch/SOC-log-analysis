import os
from datetime import datetime


class ReportGenerator:

    def __init__(self):

        self.report_folder = "reports"

        os.makedirs(self.report_folder, exist_ok=True)

    def generate_daily_report(self, alerts):

        report_path = os.path.join(
            self.report_folder,
            "daily_report.txt"
        )

        critical = 0
        high = 0
        medium = 0

        for alert in alerts:

            if "CRITICAL" in alert:
                critical += 1

            elif "HIGH" in alert:
                high += 1

            else:
                medium += 1

        with open(report_path, "w") as file:

            file.write("=" * 50 + "\n")
            file.write("SOC DAILY REPORT\n")
            file.write("=" * 50 + "\n\n")

            file.write(
                f"Generated : {datetime.now()}\n\n"
            )

            file.write(
                f"Total Alerts : {len(alerts)}\n"
            )

            file.write(
                f"Critical : {critical}\n"
            )

            file.write(
                f"High : {high}\n"
            )

            file.write(
                f"Medium : {medium}\n\n"
            )

            file.write("Alert Details\n")
            file.write("-" * 50 + "\n")

            for alert in alerts:

                file.write(alert + "\n")

        return report_path