from pathlib import Path
from google_auth_oauthlib.flow import InstalledAppFlow

CONFIG_DIR = Path.home() / ".config" / "threat-intel-bot"
CLIENT_FILE = CONFIG_DIR / "google-oauth-client.json"
TOKEN_FILE = CONFIG_DIR / "gmail-token.json"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.send"
]


def authorize_gmail():
    if not CLIENT_FILE.is_file():
        raise FileNotFoundError("Google OAuth credentials not found")

    if TOKEN_FILE.exists():
        print("OAuth token already exists. Not overwriting.")
        return

    flow = InstalledAppFlow.from_client_secrets_file(
        str(CLIENT_FILE),
        scopes=SCOPES
    )

    credentials = flow.run_local_server(
        host="127.0.0.1",
        port=0,
        open_browser=True
    )

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    with TOKEN_FILE.open("w", encoding="utf-8") as file:
        file.write(credentials.to_json())

    TOKEN_FILE.chmod(0o600)

    print("PASS: Gmail authorization completed")
    print("PASS: OAuth token saved securely")
    print("PASS: Gmail send-only permission configured")


if __name__ == "__main__":
    authorize_gmail()
