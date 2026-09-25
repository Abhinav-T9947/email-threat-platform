import hashlib


def calculate_sha256(file_bytes):
    """
    Calculate the SHA-256 hash of the provided file bytes.
    """

    sha256_hash = hashlib.sha256()

    sha256_hash.update(file_bytes)

    return sha256_hash.hexdigest()


if __name__ == "__main__":

    test_data = b"Email Threat Detection Test"

    result = calculate_sha256(test_data)

    print("=== SHA-256 TEST ===")
    print("SHA-256:", result)

