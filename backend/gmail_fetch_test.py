import base64
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOKEN_FILE = PROJECT_ROOT / "token.json"
OUTPUT_FILE = PROJECT_ROOT / "email_forensics" / "gmail_ingested_test.eml"

READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
TEST_SUBJECT = "MailSentinel Ingestion Test"


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

    service = build("gmail", "v1", credentials=credentials)

    # Search only for the controlled test message.
    results = service.users().messages().list(
        userId="me",
        q='subject:"MailSentinel Ingestion Test"',
        maxResults=10,
    ).execute()

    messages = results.get("messages", [])

    if not messages:
        print("No matching test email found.")
        print("Check the inbox and confirm the subject is exact.")
        return

    # Inspect matching messages and select one whose subject is exact.
    for message_ref in messages:
        message = service.users().messages().get(
            userId="me",
            id=message_ref["id"],
            format="full",
        ).execute()

        headers = message.get("payload", {}).get("headers", [])
        subject = next(
            (
                header["value"]
                for header in headers
                if header.get("name", "").lower() == "subject"
            ),
            "",
        )

        if subject.strip() == TEST_SUBJECT:
            raw_message = service.users().messages().get(
                userId="me",
                id=message_ref["id"],
                format="raw",
            ).execute()

            raw_data = raw_message["raw"]
            email_bytes = base64.urlsafe_b64decode(
                raw_data + "=" * (-len(raw_data) % 4)
            )

            OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT_FILE.write_bytes(email_bytes)

            print("Test email fetched successfully.")
            print(f"Saved as: {OUTPUT_FILE.relative_to(PROJECT_ROOT)}")
            print("Gmail message was not modified or deleted.")
            return

    print("No exact subject match found.")


if __name__ == "__main__":
    main()