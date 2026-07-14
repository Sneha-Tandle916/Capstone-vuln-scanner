from notifications.notifier import send_notification

message = """
Vulnerability Scan Completed

HIGH Vulnerabilities : 2
CRITICAL Vulnerabilities : 0

Report generated successfully.
"""

send_notification(message)