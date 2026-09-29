from sqlalchemy import create_engine, Column, String, Integer, DateTime, text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timezone
import os


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATABASE_PATH = os.path.join(
    BASE_DIR,
    "backend",
    "forensic_cases.db"
)

DATABASE_URL = (
    f"sqlite:///{DATABASE_PATH}"
)


engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False
    }
)


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


Base = declarative_base()


class ForensicCase(Base):

    __tablename__ = "forensic_cases"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    owner_google_sub = Column(String, nullable=True, index=True)

    case_id = Column(
        String,
        unique=True,
        nullable=False,
        index=True
    )

    evidence_sha256 = Column(
        String,
        nullable=False
    )

    report_sha256 = Column(
        String,
        nullable=False
    )

    transaction_hash = Column(
        String,
        nullable=False
    )

    block_number = Column(
        Integer,
        nullable=False
    )

    created_at = Column(
        DateTime,
        nullable=False
    )

class GmailAccount(Base):
    __tablename__ = "gmail_accounts"

    id = Column(Integer, primary_key=True, index=True)
    google_sub = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, nullable=False, index=True)
    encrypted_credentials = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)

def initialize_database():

    Base.metadata.create_all(bind=engine)

    # Add the owner column to existing databases without deleting cases.
    with engine.begin() as connection:
        columns = {
            row[1]
            for row in connection.execute(
                text("PRAGMA table_info(forensic_cases)")
            )
        }

        if "owner_google_sub" not in columns:
            connection.execute(
                text("ALTER TABLE forensic_cases ADD COLUMN owner_google_sub VARCHAR")
            )



def create_case(
    case_id,
    evidence_sha256,
    report_sha256,
    transaction_hash,
    block_number,
    owner_google_sub
):

    db = SessionLocal()

    try:

        case = ForensicCase(
            case_id=case_id,
            owner_google_sub=owner_google_sub,
            evidence_sha256=evidence_sha256,
            report_sha256=report_sha256,
            transaction_hash=transaction_hash,
            block_number=block_number,
            created_at=datetime.now(
                timezone.utc
            )
        )

        db.add(case)

        db.commit()

        db.refresh(case)

        return case

    finally:

        db.close()


def get_case(case_id, owner_google_sub):

    db = SessionLocal()

    try:
        return (
            db.query(ForensicCase)
            .filter(
                ForensicCase.case_id == case_id,
                ForensicCase.owner_google_sub == owner_google_sub
            )
            .first()
        )

    finally:
        db.close()
def get_case_by_evidence_hash(evidence_sha256, owner_google_sub):
    db = SessionLocal()

    try:
        return (
            db.query(ForensicCase)
            .filter(
                ForensicCase.evidence_sha256 == evidence_sha256,
                ForensicCase.owner_google_sub == owner_google_sub
            )
            .first()
        )

    finally:
        db.close()
def save_gmail_account(google_sub, email, encrypted_credentials):
    db = SessionLocal()
    now = datetime.now(timezone.utc)

    try:
        account = (
            db.query(GmailAccount)
            .filter(GmailAccount.google_sub == google_sub)
            .first()
        )

        if account:
            account.email = email
            account.encrypted_credentials = encrypted_credentials
            account.updated_at = now
        else:
            account = GmailAccount(
                google_sub=google_sub,
                email=email,
                encrypted_credentials=encrypted_credentials,
                created_at=now,
                updated_at=now,
            )
            db.add(account)

        db.commit()
        db.refresh(account)
        return account

    finally:
        db.close()


def get_gmail_account(google_sub):
    db = SessionLocal()

    try:
        return (
            db.query(GmailAccount)
            .filter(GmailAccount.google_sub == google_sub)
            .first()
        )

    finally:
        db.close()
if __name__ == "__main__":

    print(
        "=== DATABASE INITIALIZATION ==="
    )

    initialize_database()

    print()
    print(
        "SQLite database created:"
    )

    print(
        DATABASE_PATH
    )