"""
Email notifications (optional).

If an SMTP server is configured (WEBVULN_SMTP_HOST etc.) and the user turned
the option on in "Account", they get a short email when their scan finishes.
Without SMTP settings this does nothing.
"""

import logging
import smtplib
from email.message import EmailMessage

from config import settings

logger = logging.getLogger(__name__)


def email_enabled():
    return bool(settings.SMTP_HOST and settings.SMTP_FROM)


def build_message(to_address, scan):
    message = EmailMessage()
    message["From"] = settings.SMTP_FROM
    message["To"] = to_address
    message["Subject"] = f"WebVuln Scanner: scan #{scan['id']} {scan['status']}"
    link = f"{settings.PUBLIC_BASE_URL}/scans/{scan['id']}" if settings.PUBLIC_BASE_URL else ""
    message.set_content(
        f"Your scan of {scan['target_url']} has {scan['status']}.\n"
        f"Findings: {scan['finding_count']}\n"
        + (f"Open the results: {link}\n" if link else "")
        + "\nYou get this email because you turned on scan notifications in your account."
    )
    return message


def send_scan_finished(to_address, scan):
    """Send the email. Errors are logged, never raised (a scan must not fail because of email)."""
    if not email_enabled() or not to_address:
        return False
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as smtp:
            smtp.starttls()
            if settings.SMTP_USER:
                smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            smtp.send_message(build_message(to_address, scan))
        return True
    except (OSError, smtplib.SMTPException) as error:
        logger.warning("Could not send email to %s: %s", to_address, error)
        return False
