import hashlib
import json
import uuid
from datetime import datetime, timezone


def generate_case_id():
    """
    Generate a unique forensic case ID.

    Example:
    CASE-20260923-A1B2C3D4
    """

    date_part = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d")

    unique_part = uuid.uuid4().hex[:8].upper()

    return f"CASE-{date_part}-{unique_part}"


def calculate_report_sha256(forensic_result):
    """
    Calculate a deterministic SHA-256 hash
    of the forensic analysis result.

    JSON keys are sorted so that the same
    forensic result produces the same hash.
    """

    canonical_json = json.dumps(
        forensic_result,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )

    return hashlib.sha256(
        canonical_json.encode("utf-8")
    ).hexdigest()


def build_integrity_record(
    evidence_hash,
    forensic_result
):
    """
    Build the complete evidence integrity record.
    """

    case_id = generate_case_id()

    report_hash = calculate_report_sha256(
        forensic_result
    )

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    return {
        "case_id": case_id,
        "evidence_sha256": evidence_hash,
        "report_sha256": report_hash,
        "hash_algorithm": "SHA-256",
        "created_at": timestamp
    }


if __name__ == "__main__":

    print("=== FORENSIC INTEGRITY TEST ===")

    test_result = {
        "prediction": "phishing",
        "risk_level": "high",
        "score": 100
    }

    test_evidence_hash = (
        "2d92465ec06dcd7bc49b9b867857f8cdb027e7707c3b6d65dbccbee3b076003e"
    )

    integrity = build_integrity_record(
        test_evidence_hash,
        test_result
    )

    print()
    print("Case ID:")
    print(integrity["case_id"])

    print()
    print("Evidence SHA-256:")
    print(integrity["evidence_sha256"])

    print()
    print("Report SHA-256:")
    print(integrity["report_sha256"])

    print()
    print("Hash Algorithm:")
    print(integrity["hash_algorithm"])

    print()
    print("Created At:")
    print(integrity["created_at"])

