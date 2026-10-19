from __future__ import annotations

import asyncio
import logging
import os
import smtplib
from email.message import EmailMessage

logger = logging.getLogger("app.email")


def confirmation_url(raw_token: str) -> str:
    base = os.getenv("APP_URL", "http://127.0.0.1:8000").rstrip("/")
    return f"{base}/api/auth/confirm?token={raw_token}"


async def send_confirmation_email(recipient: str, name: str, url: str) -> None:
    """Log the confirm URL. Send mail only when ``SMTP_HOST`` is set.

    Signup still succeeds when SMTP is unset or the send fails. The URL is the
    stand-in for a mail body, so application logs contain the verify token.
    """
    logger.info("confirmation url for %s: %s", recipient, url)
    host = os.getenv("SMTP_HOST", "").strip()
    if not host:
        return

    port = int(os.getenv("SMTP_PORT", "587") or "587")
    mail_from = os.getenv("MAIL_FROM", "noreply@example.com")
    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    use_tls = os.getenv("SMTP_TLS", "1") == "1"

    def _send() -> None:
        msg = EmailMessage()
        msg["From"] = mail_from
        msg["To"] = recipient
        msg["Subject"] = "Confirm your email"
        msg.set_content(f"Hi {name},\n\nConfirm your email by visiting: {url}\n")
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            if use_tls:
                smtp.starttls()
            if username:
                smtp.login(username, password)
            smtp.send_message(msg)

    try:
        await asyncio.to_thread(_send)
    except Exception:
        logger.warning("confirmation email could not be sent to %s", recipient)
