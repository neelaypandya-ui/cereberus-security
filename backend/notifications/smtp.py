"""SMTP notification sender — sends dark-themed HTML emails."""

import asyncio
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from ..utils.logging import get_logger

logger = get_logger("notifications.smtp")

# Dark-themed HTML email template
_EMAIL_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body {{
    margin: 0;
    padding: 0;
    background-color: #0a0e17;
    color: #c8ccd4;
    font-family: 'Segoe UI', Consolas, monospace;
}}
.container {{
    max-width: 600px;
    margin: 0 auto;
    padding: 20px;
}}
.header {{
    background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%);
    border: 1px solid #30363d;
    border-bottom: 2px solid #00ff88;
    padding: 20px;
    text-align: center;
}}
.header h1 {{
    color: #00ff88;
    margin: 0;
    font-size: 18px;
    letter-spacing: 3px;
    text-transform: uppercase;
}}
.header .classification {{
    color: #ff4444;
    font-size: 10px;
    letter-spacing: 2px;
    margin-top: 8px;
}}
.body-content {{
    background-color: #161b22;
    border: 1px solid #30363d;
    border-top: none;
    padding: 24px;
    line-height: 1.6;
}}
.subject-line {{
    color: #e6edf3;
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 16px;
    padding-bottom: 12px;
    border-bottom: 1px solid #30363d;
}}
.footer {{
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-top: none;
    padding: 16px;
    text-align: center;
    font-size: 11px;
    color: #666;
}}
.footer a {{
    color: #00ff88;
    text-decoration: none;
}}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Cereberus Defense Network</h1>
        <div class="classification">AUTOMATED NOTIFICATION</div>
    </div>
    <div class="body-content">
        <div class="subject-line">{subject}</div>
        {body}
    </div>
    <div class="footer">
        CEREBERUS DEFENSE SYSTEM &mdash; Automated notification. Do not reply.
    </div>
</div>
</body>
</html>"""


class SMTPSender:
    """Sends email notifications via SMTP with a dark-themed HTML template.

    The actual SMTP send is run in a thread executor to avoid blocking
    the async event loop.
    """

    async def send(self, config: dict, subject: str, body_html: str, to: str) -> bool:
        """Send an HTML email via SMTP.

        Args:
            config: SMTP configuration dictionary with keys:
                - host: SMTP server hostname
                - port: SMTP server port
                - username: SMTP auth username
                - password: SMTP auth password
                - from_addr: Sender email address
            subject: Email subject line.
            body_html: HTML content for the email body.
            to: Recipient email address.

        Returns:
            True if the email was sent successfully, False otherwise.
        """
        host = config.get("host", "")
        port = config.get("port", 587)
        username = config.get("username", "")
        password = config.get("password", "")
        from_addr = config.get("from_addr", username)

        if not host or not to:
            logger.error("smtp_missing_config", host=host, to=to)
            return False

        # Build the full HTML email using the dark-themed template
        full_html = _EMAIL_TEMPLATE.format(subject=subject, body=body_html)

        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None,
                self._send_sync,
                host,
                port,
                username,
                password,
                from_addr,
                to,
                subject,
                full_html,
            )
            logger.info("smtp_email_sent", to=to, subject=subject)
            return True
        except Exception as exc:
            logger.error("smtp_send_error", to=to, error=str(exc))
            return False

    @staticmethod
    def _send_sync(
        host: str,
        port: int,
        username: str,
        password: str,
        from_addr: str,
        to: str,
        subject: str,
        html_body: str,
    ) -> None:
        """Synchronous SMTP send — executed in a thread pool."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to

        # Attach HTML body
        html_part = MIMEText(html_body, "html", "utf-8")
        msg.attach(html_part)

        with smtplib.SMTP(host, port, timeout=30) as server:
            server.ehlo()
            if port != 25:
                server.starttls()
                server.ehlo()
            if username and password:
                server.login(username, password)
            server.sendmail(from_addr, [to], msg.as_string())
