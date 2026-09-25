import re


def extract_domain_from_email(email_address):
    """
    Extract the domain from an email address.

    Example:
    alerts@example.com -> example.com
    """

    if not email_address:
        return None

    match = re.search(
        r"<([^<>@\s]+@[^<>@\s]+)>",
        email_address
    )

    if match:
        email_address = match.group(1)

    email_address = email_address.strip()

    if "@" not in email_address:
        return None

    return email_address.rsplit(
        "@",
        1
    )[1].lower()


def extract_authentication_domains(authentication_results):
    """
    Extract SPF, DKIM, and DMARC-related domains
    from Authentication-Results headers.
    """

    combined_results = " ".join(
        authentication_results
    ).lower()

    result = {
        "spf_domain": None,
        "dkim_domain": None,
        "dmarc_domain": None
    }

    # SPF domain
    spf_match = re.search(
        r"\bspf=[^;\s]+(?:\s+smtp\.mailfrom=([^;\s]+))?",
        combined_results
    )

    if spf_match and spf_match.group(1):
        result["spf_domain"] = spf_match.group(1)

    # DKIM domain
    dkim_match = re.search(
        r"\bdkim=[^;\s]+(?:\s+d=([^;\s]+))?",
        combined_results
    )

    if dkim_match and dkim_match.group(1):
        result["dkim_domain"] = dkim_match.group(1)

    # DMARC domain
    dmarc_match = re.search(
        r"\bdmarc=[^;\s]+(?:\s+header\.from=([^;\s]+))?",
        combined_results
    )

    if dmarc_match and dmarc_match.group(1):
        result["dmarc_domain"] = dmarc_match.group(1)

    return result


def analyze_authentication(
    authentication_results,
    from_header,
    return_path
):
    """
    Analyze SPF, DKIM, and DMARC results
    and compare their domains with the visible
    From and Return-Path domains.
    """

    combined_results = " ".join(
        authentication_results
    ).lower()

    # --------------------------------
    # AUTHENTICATION RESULTS
    # --------------------------------

    spf_match = re.search(
        r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        combined_results
    )

    dkim_match = re.search(
        r"\bdkim=(pass|fail|none|neutral|temperror|permerror)\b",
        combined_results
    )

    dmarc_match = re.search(
        r"\bdmarc=(pass|fail|none|bestguesspass|temperror|permerror)\b",
        combined_results
    )

    spf = (
        spf_match.group(1)
        if spf_match
        else "unknown"
    )

    dkim = (
        dkim_match.group(1)
        if dkim_match
        else "unknown"
    )

    dmarc = (
        dmarc_match.group(1)
        if dmarc_match
        else "unknown"
    )

    # --------------------------------
    # DOMAINS
    # --------------------------------

    from_domain = extract_domain_from_email(
        from_header
    )

    return_path_domain = extract_domain_from_email(
        return_path
    )

    authentication_domains = (
        extract_authentication_domains(
            authentication_results
        )
    )

    spf_domain = authentication_domains[
        "spf_domain"
    ]

    dkim_domain = authentication_domains[
        "dkim_domain"
    ]

    dmarc_domain = authentication_domains[
        "dmarc_domain"
    ]

    # --------------------------------
    # DOMAIN ALIGNMENT
    # --------------------------------

    spf_aligned = None

    if from_domain and return_path_domain:

        spf_aligned = (
            from_domain == return_path_domain
        )

    dkim_aligned = None

    if from_domain and dkim_domain:

        dkim_aligned = (
            from_domain == dkim_domain
        )

    dmarc_aligned = None

    if from_domain and dmarc_domain:

        dmarc_aligned = (
            from_domain == dmarc_domain
        )

    # --------------------------------
    # RETURN RESULTS
    # --------------------------------

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,

        "from_domain": from_domain,

        "return_path_domain": return_path_domain,

        "spf_domain": spf_domain,

        "dkim_domain": dkim_domain,

        "dmarc_domain": dmarc_domain,

        "alignment": {
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "dmarc_aligned": dmarc_aligned
        }
    }


if __name__ == "__main__":

    authentication_results = [
        "mail.example.com; "
        "spf=fail smtp.mailfrom=fake-security.example; "
        "dkim=fail d=fake-security.example; "
        "dmarc=fail header.from=example.com"
    ]

    result = analyze_authentication(
        authentication_results,
        "Security Team <security@example.com>",
        "<alerts@fake-security.example>"
    )

    print(
        "=== AUTHENTICATION ANALYSIS ==="
    )

    for key, value in result.items():

        print(
            f"{key}: {value}"
        )