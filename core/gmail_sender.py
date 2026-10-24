import base64
import os
import tempfile
from email.message import EmailMessage
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


TOKEN_FILE = (
    Path.home() / ".config/threat-intel-bot/gmail-token.json"
)

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]


def load_credentials():
    credentials = Credentials.from_authorized_user_file(
        str(TOKEN_FILE), SCOPES
    )

    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())

        fd, temp_name = tempfile.mkstemp(
            dir=TOKEN_FILE.parent,
            prefix=".gmail-token-"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                file.write(credentials.to_json())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, TOKEN_FILE)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    if not credentials.valid:
        raise RuntimeError("Gmail authorization is invalid or expired")

    return credentials


def send_gmail_alert(sender, recipient, indicator, title, message, severity):
    for value in (sender, recipient, indicator, title, severity):
        if not isinstance(value, str) or "\n" in value or "\r" in value:
            raise ValueError("Invalid email alert field")

    email = EmailMessage()
    email["From"] = sender
    email["To"] = recipient
    email["Subject"] = f"[{severity}] Threat Intel Alert - {title}"

    email.set_content(
        "Automated Threat Intelligence Alert\n\n"
        f"Indicator: {indicator}\n"
        f"Severity: {severity}\n"
        f"Event: {title}\n\n"
        f"{message}\n\n"
        "Review the IOC in your local SOC dashboard."
    )

    encoded = base64.urlsafe_b64encode(
        email.as_bytes()
    ).decode("ascii")

    service = build(
        "gmail", "v1",
        credentials=load_credentials(),
        cache_discovery=False
    )

    result = service.users().messages().send(
        userId="me",
        body={"raw": encoded}
    ).execute()

    return result.get("id")


if __name__ == "__main__":
    print("PASS: Gmail API sender module available")
    print("PASS: No email sent")
