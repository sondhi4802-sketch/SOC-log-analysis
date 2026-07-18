import re


class LogParser:

    def __init__(self, log_file):

        self.log_file = log_file

        self.logs = self.read_logs()

    # Read all logs
    def read_logs(self):

        try:
            with open(self.log_file, "r") as file:
                return [line.strip() for line in file if line.strip()]

        except FileNotFoundError:
            return []

    # Total logs
    def total_logs(self):

        return len(self.logs)

    # Failed Login Logs
    def failed_login_logs(self):

        return [log for log in self.logs if "FAILED LOGIN" in log.upper()]

    # Admin Login Logs
    def admin_login_logs(self):

        return [log for log in self.logs if "ADMIN LOGIN" in log.upper()]

    # SQL Injection Logs
    def sql_injection_logs(self):

        return [log for log in self.logs if "SQL INJECTION" in log.upper()]

    # Suspicious IP Logs
    def suspicious_ip_logs(self):

        return [log for log in self.logs if "SUSPICIOUS IP" in log.upper()]

    # Count Functions

    def failed_login_count(self):

        return len(self.failed_login_logs())

    def admin_login_count(self):

        return len(self.admin_login_logs())

    def sql_injection_count(self):

        return len(self.sql_injection_logs())

    def suspicious_ip_count(self):

        return len(self.suspicious_ip_logs())

    # Extract IP Address
    def extract_ips(self):

        ips = []

        pattern = r"(?:\d{1,3}\.){3}\d{1,3}"

        for log in self.logs:

            match = re.search(pattern, log)

            if match:
                ips.append(match.group())

        return ips

    # Search Logs
    def search_logs(self, keyword):

        return [log for log in self.logs if keyword.upper() in log.upper()]