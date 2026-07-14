import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def send_notification(message: str):
    """
    Send a notification.
    Currently prints to console.
    Can later be extended for Slack or Email.
    """

    logger.info("Sending notification...")

    print("\n" + "=" * 60)
    print("SECURITY NOTIFICATION")
    print("=" * 60)
    print(message)
    print("=" * 60)

    logger.info("Notification sent successfully.")