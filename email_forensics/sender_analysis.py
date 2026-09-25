from email.utils import parseaddr
from urllib.parse import urlparse


def extract_email_domain(email_address):
    """
    Extract the domain from an email address.
    """

    if not email_address:
        return None

    _, address = parseaddr(email_address)

    if "@" not in address:
        return None

    return address.split("@", 1)[1].lower()


def analyze_sender(
    from_header,
    return_path,
    reply_to
):
    """
    Analyze relationships between:
    - From
    - Return-Path
    - Reply-To
    """

    from_domain = extract_email_domain(
        from_header
    )

    return_path_domain = extract_email_domain(
        return_path
    )

    reply_to_domain = extract_email_domain(
        reply_to
    )

    return_path_mismatch = False
    reply_to_mismatch = False

    if (
        from_domain
        and return_path_domain
    ):
        return_path_mismatch = (
            from_domain
            != return_path_domain
        )

    if (
        from_domain
        and reply_to_domain
    ):
        reply_to_mismatch = (
            from_domain
            != reply_to_domain
        )

    return {
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_mismatch": return_path_mismatch,
        "reply_to_mismatch": reply_to_mismatch
    }


if __name__ == "__main__":

    result = analyze_sender(
        "Security Team <security@example.com>",
        "<alerts@fake-security.example>",
        "support@fake-security.example"
    )

    print("=== SENDER ANALYSIS ===")
    print(result)