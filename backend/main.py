from fastapi import (
    FastAPI,
    UploadFile,
    File,
    Form,
    HTTPException
)

from fastapi.middleware.cors import CORSMiddleware

import tempfile
import os

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
    get_case
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Email Threat Detection API",
    description="Email forensic analysis and threat detection API",
    version="1.0.0"
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
    file: UploadFile = File(...)
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
            ]
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
    case_id: str
):

    case = get_case(
        case_id
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