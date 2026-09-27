from pathlib import Path

from google_auth_oauthlib.flow import InstalledAppFlow

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CREDENTIALS_FILE = PROJECT_ROOT / "credentials.json"
TOKEN_FILE = PROJECT_ROOT / "token.json"

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def main():
    if not CREDENTIALS_FILE.exists():
        raise FileNotFoundError(
            f"OAuth credentials not found: {CREDENTIALS_FILE}"
        )

    if TOKEN_FILE.exists():
        print("A Gmail token already exists. No new login was started.")
        return

    flow = InstalledAppFlow.from_client_secrets_file(
        str(CREDENTIALS_FILE),
        SCOPES,
    )

    credentials = flow.run_local_server(
        port=0,
        open_browser=True,
    )

    TOKEN_FILE.write_text(credentials.to_json(), encoding="utf-8")

    print("Gmail authorization successful.")
    print(f"Token saved locally: {TOKEN_FILE.name}")
    print("Granted scope: Gmail read-only")


if __name__ == "__main__":
    main()