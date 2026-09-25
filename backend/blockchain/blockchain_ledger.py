from web3 import Web3
import os
from dotenv import load_dotenv

load_dotenv()

class BlockchainLedger:
    """
    Persistent local Ethereum-compatible blockchain ledger
    using a Ganache JSON-RPC node.

    Only metadata and cryptographic hashes are stored.
    The original email is never stored on-chain.
    """

    # Ganache persistent JSON-RPC endpoint.
    RPC_URL = os.getenv("GANACHE_RPC_URL")

    # Ganache account 0 private key.
    # This key is for this local development blockchain only.
    PRIVATE_KEY = os.getenv("GANACHE_PRIVATE_KEY")
    def __init__(self):
        self.web3 = Web3(
            Web3.HTTPProvider(self.RPC_URL)
        )

        if not self.web3.is_connected():
            raise RuntimeError(
                "Could not connect to Ganache blockchain at "
                f"{self.RPC_URL}"
            )

        account = self.web3.eth.account.from_key(
            self.PRIVATE_KEY
        )

        self.account = account.address

    def get_blockchain_status(self):
        return {
            "connected": self.web3.is_connected(),
            "network_id": self.web3.eth.chain_id,
            "block_number": self.web3.eth.block_number,
            "account": self.account
        }

    def create_record(
        self,
        case_id,
        evidence_sha256,
        report_sha256
    ):
        data_string = (
            f"CASE_ID:{case_id}|"
            f"EVIDENCE_SHA256:{evidence_sha256}|"
            f"REPORT_SHA256:{report_sha256}"
        )

        data_hex = (
            "0x"
            + data_string.encode("utf-8").hex()
        )

        nonce = self.web3.eth.get_transaction_count(
            self.account
        )

        transaction = {
            "from": self.account,
            "to": self.account,
            "value": 0,
            "data": data_hex,
            "gas": 100000,
            "gasPrice": self.web3.eth.gas_price,
            "nonce": nonce,
            "chainId": self.web3.eth.chain_id
        }

        signed_transaction = (
            self.web3.eth.account.sign_transaction(
                transaction,
                self.PRIVATE_KEY
            )
        )

        transaction_hash = (
            self.web3.eth.send_raw_transaction(
                signed_transaction.raw_transaction
            )
        )

        receipt = (
            self.web3.eth.wait_for_transaction_receipt(
                transaction_hash
            )
        )

        return {
            "transaction_hash":
                transaction_hash.hex(),

            "block_number":
                receipt["blockNumber"],

            "case_id":
                case_id,

            "evidence_sha256":
                evidence_sha256,

            "report_sha256":
                report_sha256
        }

    def get_record_from_transaction(
        self,
        transaction_hash
    ):
        transaction = (
            self.web3.eth.get_transaction(
                transaction_hash
            )
        )

        raw_data = transaction["input"]

        if isinstance(raw_data, bytes):
            decoded_data = raw_data.decode(
                "utf-8"
            )
        else:
            if raw_data.startswith("0x"):
                raw_data = raw_data[2:]

            decoded_data = bytes.fromhex(
                raw_data
            ).decode("utf-8")

        parts = decoded_data.split("|")
        record = {}

        for part in parts:
            if ":" not in part:
                continue

            key, value = part.split(":", 1)

            if key == "CASE_ID":
                record["case_id"] = value

            elif key == "EVIDENCE_SHA256":
                record["evidence_sha256"] = value

            elif key == "REPORT_SHA256":
                record["report_sha256"] = value

        record["transaction_hash"] = (
            transaction_hash
        )

        record["block_number"] = (
            transaction["blockNumber"]
        )

        return record

    def verify_record(
        self,
        transaction_hash,
        evidence_sha256,
        report_sha256
    ):
        blockchain_record = (
            self.get_record_from_transaction(
                transaction_hash
            )
        )

        evidence_match = (
            blockchain_record.get(
                "evidence_sha256"
            )
            == evidence_sha256
        )

        report_match = (
            blockchain_record.get(
                "report_sha256"
            )
            == report_sha256
        )

        if evidence_match and report_match:
            verification_status = "VERIFIED"
        else:
            verification_status = (
                "INTEGRITY MISMATCH"
            )

        return {
            "verification_status":
                verification_status,

            "evidence_match":
                evidence_match,

            "report_match":
                report_match,

            "blockchain_record":
                blockchain_record
        }