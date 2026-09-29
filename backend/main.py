import base64
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


from fastapi import (
    FastAPI,
    UploadFile,
    File,
    Form,
    HTTPException,
    Query
)

from fastapi.middleware.cors import CORSMiddleware

import tempfile
import os
import json

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import Request as FastAPIRequest
from fastapi.responses import RedirectResponse
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from starlette.middleware.sessions import SessionMiddleware

from email_forensics.eml_parser import parse_eml

from backend.evidence_hash import (
    calculate_sha256
)

from email_forensics.forensic_integrity import (
    build_integrity_record,
    calculate_report_sha256
)

from backend.blockchain.blockchain_ledger import (
    BlockchainLedger
)

from backend.database import (
    initialize_database,
    create_case,
    get_case,
    get_case_by_evidence_hash,
    save_gmail_account,
    get_gmail_account
)

# ============================================================
# GOOGLE OAUTH CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(PROJECT_ROOT / ".env")

GOOGLE_OAUTH_CLIENT_FILE = (
    PROJECT_ROOT / os.environ["GOOGLE_OAUTH_CLIENT_FILE"]
)

GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/google/callback"

GMAIL_OAUTH_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.readonly",
]
# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Email Threat Detection API",
    description="Email forensic analysis and threat detection API",
    version="1.0.0"
)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ["MAILSENTINEL_SESSION_SECRET"],
    same_site="lax",
    https_only=False,
)
# ============================================================
# CORS CONFIGURATION
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# BLOCKCHAIN + DATABASE INITIALIZATION
# ============================================================

blockchain_ledger = BlockchainLedger()

initialize_database()

def get_current_google_sub(request: FastAPIRequest):
    google_sub = request.session.get("google_sub")

    if not google_sub or not get_gmail_account(google_sub):
        request.session.clear()
        raise HTTPException(
            status_code=401,
            detail="Connect your Google account first."
        )

    return google_sub


def get_current_gmail_credentials(request: FastAPIRequest):
    google_sub = request.session.get("google_sub")

    if not google_sub:
        raise HTTPException(
            status_code=401,
            detail="Connect your Gmail account first."
        )

    account = get_gmail_account(google_sub)

    if not account:
        request.session.clear()
        raise HTTPException(
            status_code=401,
            detail="Gmail connection not found. Please connect again."
        )

    try:
        cipher = Fernet(
            os.environ["MAILSENTINEL_TOKEN_KEY"].encode("utf-8")
        )

        credentials_json = cipher.decrypt(
            account.encrypted_credentials.encode("utf-8")
        ).decode("utf-8")

        credentials = Credentials.from_authorized_user_info(
            json.loads(credentials_json),
            scopes=GMAIL_OAUTH_SCOPES
        )

        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())

            encrypted_credentials = cipher.encrypt(
                credentials.to_json().encode("utf-8")
            ).decode("utf-8")

            save_gmail_account(
                google_sub,
                account.email,
                encrypted_credentials
            )

        if not credentials.valid:
            raise HTTPException(
                status_code=401,
                detail="Gmail authorization expired. Please connect again."
            )

        return credentials

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Could not load Gmail authorization. Please connect Gmail again."
        )
@app.get("/auth/google/login")
def google_login(request: FastAPIRequest):
    flow = Flow.from_client_secrets_file(
        str(GOOGLE_OAUTH_CLIENT_FILE),
        scopes=GMAIL_OAUTH_SCOPES,
        redirect_uri=GOOGLE_REDIRECT_URI,
    )

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )

    request.session["oauth_state"] = state
    request.session["oauth_code_verifier"] = flow.code_verifier

    return RedirectResponse(authorization_url)

@app.get("/auth/google/callback")
def google_callback(request: FastAPIRequest):
    expected_state = request.session.get("oauth_state")
    received_state = request.query_params.get("state")

    if not expected_state or received_state != expected_state:
        request.session.clear()
        raise HTTPException(
            status_code=400,
            detail="Invalid OAuth state. Please try connecting Gmail again."
        )

    if request.query_params.get("error"):
        request.session.clear()
        raise HTTPException(
            status_code=400,
            detail="Google authorization was not completed."
        )

    flow = Flow.from_client_secrets_file(
        str(GOOGLE_OAUTH_CLIENT_FILE),
        scopes=GMAIL_OAUTH_SCOPES,
        state=expected_state,
        redirect_uri=GOOGLE_REDIRECT_URI,
    )

    flow.code_verifier = request.session.get("oauth_code_verifier")
    if not flow.code_verifier:
        request.session.clear()
        raise HTTPException(
            status_code=400,
            detail="OAuth session expired. Please connect Gmail again."
        )

    flow.fetch_token(authorization_response=str(request.url))
    credentials = flow.credentials

    identity = id_token.verify_oauth2_token(
        credentials.id_token,
        Request(),
        audience=flow.client_config["client_id"],
    )

    google_sub = identity["sub"]
    email = identity.get("email")

    if not email or not identity.get("email_verified"):
        raise HTTPException(
            status_code=400,
            detail="Google did not provide a verified email address."
        )

    cipher = Fernet(
        os.environ["MAILSENTINEL_TOKEN_KEY"].encode("utf-8")
    )

    encrypted_credentials = cipher.encrypt(
        credentials.to_json().encode("utf-8")
    ).decode("utf-8")

    save_gmail_account(
        google_sub,
        email,
        encrypted_credentials
    )

    request.session.clear()
    request.session["google_sub"] = google_sub

    return RedirectResponse(
        "http://localhost:5500/index.html?gmail=connected"
    )

@app.get("/auth/status")
def auth_status(request: FastAPIRequest):
    google_sub = request.session.get("google_sub")

    if not google_sub:
        return {"connected": False, "email": None}

    account = get_gmail_account(google_sub)

    if not account:
        request.session.clear()
        return {"connected": False, "email": None}

    return {"connected": True, "email": account.email}


@app.post("/auth/logout")
def auth_logout(request: FastAPIRequest):
    request.session.clear()
    return {"connected": False}
# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():

    return {
        "status": "running",
        "service": "Email Threat Detection API"
    }


# ============================================================
# ANALYZE EMAIL
# ============================================================

@app.post("/analyze-email")
async def analyze_email(
    request: FastAPIRequest,
    file: UploadFile = File(...)
):
    owner_google_sub = get_current_google_sub(request)

    # --------------------------------------------------------
    # Validate file
    # --------------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No file provided"
        )

    if not file.filename.lower().endswith(".eml"):

        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported"
        )

    # --------------------------------------------------------
    # Read uploaded email
    # --------------------------------------------------------

    file_contents = await file.read()

    # --------------------------------------------------------
    # Calculate evidence SHA-256
    # --------------------------------------------------------

    evidence_hash = calculate_sha256(
        file_contents
    )

    temporary_path = None

    try:

        # ----------------------------------------------------
        # Create temporary EML file
        # ----------------------------------------------------

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".eml"
        ) as temp_file:

            temp_file.write(
                file_contents
            )

            temporary_path = temp_file.name

        # ----------------------------------------------------
        # Run forensic analysis
        # ----------------------------------------------------

        result = parse_eml(
            temporary_path
        )

        # ----------------------------------------------------
        # Build forensic integrity record
        # ----------------------------------------------------

        integrity_record = (
            build_integrity_record(
                evidence_hash,
                result
            )
        )

        # ----------------------------------------------------
        # Store hashes on blockchain
        # ----------------------------------------------------

        blockchain_record = (
            blockchain_ledger.create_record(
                integrity_record["case_id"],
                integrity_record[
                    "evidence_sha256"
                ],
                integrity_record[
                    "report_sha256"
                ]
            )
        )

        # ----------------------------------------------------
        # Immediately verify blockchain record
        # ----------------------------------------------------

        verification = (
            blockchain_ledger.verify_record(
                blockchain_record[
                    "transaction_hash"
                ],
                integrity_record[
                    "evidence_sha256"
                ],
                integrity_record[
                    "report_sha256"
                ]
            )
        )

        # ----------------------------------------------------
        # Persist case metadata in SQLite
        # ----------------------------------------------------

        create_case(
            integrity_record["case_id"],
            integrity_record[
                "evidence_sha256"
            ],
            integrity_record[
                "report_sha256"
            ],
            blockchain_record[
                "transaction_hash"
            ],
            blockchain_record[
                "block_number"
            ],
            owner_google_sub=owner_google_sub
        )

        # ----------------------------------------------------
        # Add blockchain integrity information
        # ----------------------------------------------------

        result["evidence_integrity"] = {

            "case_id":
                integrity_record[
                    "case_id"
                ],

            "evidence_sha256":
                integrity_record[
                    "evidence_sha256"
                ],

            "report_sha256":
                integrity_record[
                    "report_sha256"
                ],

            "hash_algorithm":
                integrity_record[
                    "hash_algorithm"
                ],

            "created_at":
                integrity_record[
                    "created_at"
                ],

            "blockchain": {

                "transaction_hash":
                    blockchain_record[
                        "transaction_hash"
                    ],

                "block_number":
                    blockchain_record[
                        "block_number"
                    ],

                "verification_status":
                    verification[
                        "verification_status"
                    ],

                "evidence_match":
                    verification[
                        "evidence_match"
                    ],

                "report_match":
                    verification[
                        "report_match"
                    ]
            }
        }

        return result

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )

    finally:

        if (
            temporary_path
            and os.path.exists(
                temporary_path
            )
        ):

            os.remove(
                temporary_path
            )

# ============================================================
# READ-ONLY GMAIL TEST EMAIL ANALYSIS
# ============================================================
@app.get("/gmail/search")
def search_gmail(
    request: FastAPIRequest,
    query: str = Query(
        default="newer_than:7d",
        max_length=200,
        description="Gmail search query, such as newer_than:7d or label:inbox"
    )
):
    """Search the connected user's Gmail read-only."""

    try:
        credentials = get_current_gmail_credentials(request)

        gmail_service = build(
            "gmail",
            "v1",
            credentials=credentials
        )

        search_response = (
            gmail_service.users()
            .messages()
            .list(
                userId="me",
                q=query,
                maxResults=20
            )
            .execute()
        )

        results = []

        for message in search_response.get("messages", []):
            details = (
                gmail_service.users()
                .messages()
                .get(
                    userId="me",
                    id=message["id"],
                    format="metadata",
                    metadataHeaders=["Subject", "From", "Date"]
                )
                .execute()
            )

            headers = details.get("payload", {}).get("headers", [])

            header_values = {
                header.get("name", "").lower(): header.get("value", "")
                for header in headers
            }

            results.append({
                "message_id": message["id"],
                "subject": header_values.get("subject", "(No subject)"),
                "from": header_values.get("from", ""),
                "date": header_values.get("date", "")
            })

        return {
            "query": query,
            "result_count": len(results),
            "messages": results
        }

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Gmail search failed. Please try again."
        )
@app.post("/gmail/messages/{message_id}/analyze")
def analyze_gmail_message(
    message_id: str,
    request: FastAPIRequest
):
    """Analyze a selected message from the connected Gmail account."""

    temp_path = None

    try:
        credentials = get_current_gmail_credentials(request)
        owner_google_sub = get_current_google_sub(request)

        gmail_service = build(
            "gmail",
            "v1",
            credentials=credentials
        )

        raw_message = (
            gmail_service.users()
            .messages()
            .get(
                userId="me",
                id=message_id,
                format="raw"
            )
            .execute()
        )

        raw_data = raw_message.get("raw")

        if not raw_data:
            raise HTTPException(
                status_code=404,
                detail="Gmail message was not found or did not contain raw email data."
            )

        email_bytes = base64.urlsafe_b64decode(
            raw_data + "=" * (-len(raw_data) % 4)
        )

        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".eml",
            delete=False
        ) as temp_file:
            temp_file.write(email_bytes)
            temp_path = temp_file.name

        result = parse_eml(temp_path)
        evidence_hash = calculate_sha256(email_bytes)

        # Reuse an existing case when this evidence was already analyzed.
        existing_case = get_case_by_evidence_hash(evidence_hash, owner_google_sub)

        if existing_case:
            verification = blockchain_ledger.verify_record(
                existing_case.transaction_hash,
                existing_case.evidence_sha256,
                existing_case.report_sha256
            )

            result["already_analyzed"] = True
            result["evidence_integrity"] = {
                "case_id": existing_case.case_id,
                "evidence_sha256": existing_case.evidence_sha256,
                "report_sha256": existing_case.report_sha256,
                "transaction_hash": existing_case.transaction_hash,
                "block_number": existing_case.block_number,
                "blockchain": {
                    "transaction_hash": existing_case.transaction_hash,
                    "block_number": existing_case.block_number,
                    "verification_status": verification["verification_status"],
                    "evidence_match": verification["evidence_match"],
                    "report_match": verification["report_match"]
                }
            }

            return result

        integrity_record = build_integrity_record(
            evidence_hash,
            result
        )

        blockchain_record = blockchain_ledger.create_record(
            integrity_record["case_id"],
            integrity_record["evidence_sha256"],
            integrity_record["report_sha256"]
        )

        verification = blockchain_ledger.verify_record(
            blockchain_record["transaction_hash"],
            integrity_record["evidence_sha256"],
            integrity_record["report_sha256"]
        )

        create_case(
            integrity_record["case_id"],
            integrity_record["evidence_sha256"],
            integrity_record["report_sha256"],
            blockchain_record["transaction_hash"],
            blockchain_record["block_number"],
            owner_google_sub=owner_google_sub
        )

        result["already_analyzed"] = False
        result["evidence_integrity"] = {
            "case_id": integrity_record["case_id"],
            "evidence_sha256": integrity_record["evidence_sha256"],
            "report_sha256": integrity_record["report_sha256"],
            "hash_algorithm": integrity_record["hash_algorithm"],
            "created_at": integrity_record["created_at"],
            "blockchain": {
                "transaction_hash": blockchain_record["transaction_hash"],
                "block_number": blockchain_record["block_number"],
                "verification_status": verification["verification_status"],
                "evidence_match": verification["evidence_match"],
                "report_match": verification["report_match"]
            }
        }

        return result

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Gmail message analysis failed. Please try again."
        )

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
@app.post("/analyze-gmail-test")
def analyze_gmail_test_email():
    """
    Retired legacy endpoint: it used token.json rather than the signed-in
    account session, so it must not create account-owned case records.
    """
    raise HTTPException(
        status_code=410,
        detail="This legacy test endpoint is disabled. Use the signed-in Gmail analysis feature."
    )


# MANUAL BLOCKCHAIN INTEGRITY VERIFICATION
# ============================================================

@app.post("/verify-integrity")
async def verify_integrity(
    data: dict
):

    transaction_hash = data.get(
        "transaction_hash"
    )

    evidence_sha256 = data.get(
        "evidence_sha256"
    )

    report_sha256 = data.get(
        "report_sha256"
    )

    # --------------------------------------------------------
    # Validate required fields
    # --------------------------------------------------------

    if not transaction_hash:

        raise HTTPException(
            status_code=400,
            detail="Transaction hash is required"
        )

    if not evidence_sha256:

        raise HTTPException(
            status_code=400,
            detail="Evidence SHA-256 is required"
        )

    if not report_sha256:

        raise HTTPException(
            status_code=400,
            detail="Report SHA-256 is required"
        )

    # --------------------------------------------------------
    # Verify blockchain record
    # --------------------------------------------------------

    try:

        verification = (
            blockchain_ledger.verify_record(
                transaction_hash,
                evidence_sha256,
                report_sha256
            )
        )

        return verification

    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


# ============================================================
# AUTOMATIC EVIDENCE VERIFICATION
# ============================================================

@app.post("/verify-evidence")
async def verify_evidence(
    file: UploadFile = File(...),
    transaction_hash: str = Form(...)
):

    # --------------------------------------------------------
    # Validate file
    # --------------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No file provided"
        )

    if not file.filename.lower().endswith(".eml"):

        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported"
        )

    temporary_path = None

    try:

        # ----------------------------------------------------
        # Read uploaded evidence
        # ----------------------------------------------------

        file_contents = await file.read()

        # ----------------------------------------------------
        # Calculate current evidence hash
        # ----------------------------------------------------

        current_evidence_hash = (
            calculate_sha256(
                file_contents
            )
        )

        # ----------------------------------------------------
        # Create temporary EML file
        # ----------------------------------------------------

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".eml"
        ) as temp_file:

            temp_file.write(
                file_contents
            )

            temporary_path = temp_file.name

        # ----------------------------------------------------
        # Re-run forensic analysis
        # ----------------------------------------------------

        current_forensic_result = (
            parse_eml(
                temporary_path
            )
        )

        # ----------------------------------------------------
        # Calculate current report hash
        # ----------------------------------------------------

        current_report_hash = (
            calculate_report_sha256(
                current_forensic_result
            )
        )

        # ----------------------------------------------------
        # Read blockchain record
        # ----------------------------------------------------

        blockchain_record = (
            blockchain_ledger.get_record_from_transaction(
                transaction_hash
            )
        )

        stored_evidence_hash = (
            blockchain_record.get(
                "evidence_sha256"
            )
        )

        stored_report_hash = (
            blockchain_record.get(
                "report_sha256"
            )
        )

        # ----------------------------------------------------
        # Compare evidence hashes
        # ----------------------------------------------------

        evidence_match = (
            current_evidence_hash
            == stored_evidence_hash
        )

        # ----------------------------------------------------
        # Compare forensic report hashes
        # ----------------------------------------------------

        report_match = (
            current_report_hash
            == stored_report_hash
        )

        # ----------------------------------------------------
        # Determine verification status
        # ----------------------------------------------------

        if (
            evidence_match
            and report_match
        ):

            verification_status = (
                "VERIFIED"
            )

        else:

            verification_status = (
                "INTEGRITY MISMATCH"
            )

        # ----------------------------------------------------
        # Return verification result
        # ----------------------------------------------------

        return {

            "verification_status":
                verification_status,

            "evidence_match":
                evidence_match,

            "report_match":
                report_match,

            "current_evidence_sha256":
                current_evidence_hash,

            "blockchain_evidence_sha256":
                stored_evidence_hash,

            "current_report_sha256":
                current_report_hash,

            "blockchain_report_sha256":
                stored_report_hash,

            "transaction_hash":
                transaction_hash,

            "case_id":
                blockchain_record.get(
                    "case_id"
                ),

            "block_number":
                blockchain_record.get(
                    "block_number"
                )
        }

    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    finally:

        if (
            temporary_path
            and os.path.exists(
                temporary_path
            )
        ):

            os.remove(
                temporary_path
            )


# ============================================================
# GET STORED CASE
# ============================================================

@app.get("/cases/{case_id}")
def get_stored_case(
    case_id: str,
    request: FastAPIRequest
):
    owner_google_sub = get_current_google_sub(request)

    case = get_case(
        case_id,
        owner_google_sub
    )

    if not case:

        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    return {

        "case_id":
            case.case_id,

        "evidence_sha256":
            case.evidence_sha256,

        "report_sha256":
            case.report_sha256,

        "transaction_hash":
            case.transaction_hash,

        "block_number":
            case.block_number,

        "created_at":
            case.created_at.isoformat()
    }
