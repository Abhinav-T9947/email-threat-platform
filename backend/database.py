from sqlalchemy import create_engine, Column, String, Integer, DateTime
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


def initialize_database():

    Base.metadata.create_all(
        bind=engine
    )


def create_case(
    case_id,
    evidence_sha256,
    report_sha256,
    transaction_hash,
    block_number
):

    db = SessionLocal()

    try:

        case = ForensicCase(
            case_id=case_id,
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


def get_case(case_id):

    db = SessionLocal()

    try:

        return (
            db.query(
                ForensicCase
            )
            .filter(
                ForensicCase.case_id == case_id
            )
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