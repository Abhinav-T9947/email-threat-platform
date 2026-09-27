from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOKEN_FILE = PROJECT_ROOT / "token.json"

READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def main():
    if not TOKEN_FILE.exists():
        raise FileNotFoundError("token.json not found. Run gmail_auth.py first.")

    credentials = Credentials.from_authorized_user_file(
        str(TOKEN_FILE),
        scopes=[READONLY_SCOPE],
    )

    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
        TOKEN_FILE.write_text(credentials.to_json(), encoding="utf-8")

    if READONLY_SCOPE not in (credentials.scopes or []):
        raise RuntimeError(
            "The saved token does not show the expected Gmail read-only scope."
        )

    service = build("gmail", "v1", credentials=credentials)

    profile = service.users().getProfile(userId="me").execute()

    print("Gmail API connection: SUCCESS")
    print("Read-only scope: CONFIRMED")
    print(f"Mailbox message count: {profile.get('messagesTotal', 'unknown')}")
    print("No email messages were downloaded or modified.")


if __name__ == "__main__":
    main()