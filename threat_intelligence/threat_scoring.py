def calculate_threat_score(forensic_data):
    """
    Calculate an explainable threat score from forensic evidence.

    Signals include:
    - SPF / DKIM / DMARC authentication
    - SPF / DKIM / DMARC domain alignment
    - Sender / Return-Path mismatch
    - Sender / Reply-To mismatch
    - ML phishing probability
    - IP intelligence
    - URL intelligence
    - Attachment intelligence
    - Email relay anomalies

    The final score is NOT a probability of maliciousness.
    It is an explainable development scoring system.
    """

    score = 0
    reasons = []

    # --------------------------------
    # AUTHENTICATION
    # --------------------------------

    authentication = forensic_data.get(
        "authentication",
        {}
    )

    spf = authentication.get(
        "spf",
        "unknown"
    )

    dkim = authentication.get(
        "dkim",
        "unknown"
    )

    dmarc = authentication.get(
        "dmarc",
        "unknown"
    )

    alignment = authentication.get(
        "alignment",
        {}
    )

    spf_aligned = alignment.get(
        "spf_aligned"
    )

    dkim_aligned = alignment.get(
        "dkim_aligned"
    )

    dmarc_aligned = alignment.get(
        "dmarc_aligned"
    )

    # --------------------------------
    # SPF
    # --------------------------------

    if spf == "fail":

        score += 20

        reasons.append(
            "SPF authentication failed"
        )

    elif spf == "softfail":

        score += 10

        reasons.append(
            "SPF authentication returned softfail"
        )

    # SPF alignment is additional context.
    # Do not add another score if SPF already failed.
    if (
        spf_aligned is False
        and spf not in [
            "fail",
            "softfail"
        ]
    ):

        score += 10

        reasons.append(
            "SPF domain is not aligned with "
            "the visible From domain"
        )

    # --------------------------------
    # DKIM
    # --------------------------------

    if dkim == "fail":

        score += 20

        reasons.append(
            "DKIM authentication failed"
        )

    elif dkim in [
        "temperror",
        "permerror"
    ]:

        score += 10

        reasons.append(
            "DKIM authentication returned "
            f"{dkim}"
        )

    # DKIM alignment is additional context.
    if (
        dkim_aligned is False
        and dkim not in [
            "fail",
            "temperror",
            "permerror"
        ]
    ):

        score += 10

        reasons.append(
            "DKIM domain is not aligned with "
            "the visible From domain"
        )

    # --------------------------------
    # DMARC
    # --------------------------------

    if dmarc == "fail":

        score += 20

        reasons.append(
            "DMARC authentication failed"
        )

    elif dmarc in [
        "temperror",
        "permerror"
    ]:

        score += 10

        reasons.append(
            "DMARC authentication returned "
            f"{dmarc}"
        )

    # DMARC alignment is additional context.
    if (
        dmarc_aligned is False
        and dmarc not in [
            "fail",
            "temperror",
            "permerror"
        ]
    ):

        score += 10

        reasons.append(
            "DMARC domain is not aligned with "
            "the visible From domain"
        )

    # --------------------------------
    # SENDER ANALYSIS
    # --------------------------------

    sender_analysis = forensic_data.get(
        "sender_analysis",
        {}
    )

    return_path_mismatch = sender_analysis.get(
        "return_path_mismatch",
        False
    )

    reply_to_mismatch = sender_analysis.get(
        "reply_to_mismatch",
        False
    )

    if return_path_mismatch:

        score += 10

        reasons.append(
            "Return-Path domain does not match "
            "the visible From domain"
        )

    if reply_to_mismatch:

        score += 10

        reasons.append(
            "Reply-To domain does not match "
            "the visible From domain"
        )

    # --------------------------------
    # ML PHISHING DETECTION
    # --------------------------------

    ml_analysis = forensic_data.get(
        "ml_analysis",
        {}
    )

    phishing_probability = ml_analysis.get(
        "phishing_probability",
        0.0
    )

    if phishing_probability >= 0.90:

        score += 25

        reasons.append(
            "ML model assigned high phishing probability: "
            f"{phishing_probability:.2%}"
        )

    elif phishing_probability >= 0.70:

        score += 15

        reasons.append(
            "ML model assigned elevated phishing probability: "
            f"{phishing_probability:.2%}"
        )

    # --------------------------------
    # IP INTELLIGENCE
    # --------------------------------

    ip_analysis = forensic_data.get(
        "ip_analysis",
        []
    )

    for ip_data in ip_analysis:

        classification = ip_data.get(
            "classification"
        )

        ip = ip_data.get(
            "ip"
        )

        if classification == "public":

            score += 5

            reasons.append(
                f"Public IP address found: {ip}"
            )

        elif classification == "reserved":

            score += 5

            reasons.append(
                f"Reserved IP address found: {ip}"
            )

    # --------------------------------
    # URL INTELLIGENCE
    # --------------------------------

    url_analysis = forensic_data.get(
        "url_analysis",
        []
    )

    for url_data in url_analysis:

        indicators = url_data.get(
            "indicators",
            {}
        )

        domain_data = url_data.get(
            "domain_intelligence",
            {}
        )

        url = url_data.get(
            "url"
        )

        if indicators.get(
            "uses_http"
        ):

            score += 10

            reasons.append(
                f"URL uses HTTP instead of HTTPS: {url}"
            )

        if indicators.get(
            "uses_ip_address"
        ):

            score += 15

            reasons.append(
                "URL uses an IP address instead of "
                f"a domain: {url}"
            )

        if indicators.get(
            "contains_url_encoding"
        ):

            score += 5

            reasons.append(
                f"URL contains encoded characters: {url}"
            )

        if domain_data.get(
            "has_punycode"
        ):

            score += 15

            reasons.append(
                "Domain uses Punycode: "
                f"{domain_data.get('domain')}"
            )

        if domain_data.get(
            "has_suspicious_characters"
        ):

            score += 10

            reasons.append(
                "Domain contains unusual characters: "
                f"{domain_data.get('domain')}"
            )

        if domain_data.get(
            "length",
            0
        ) > 50:

            score += 10

            reasons.append(
                "Domain is unusually long: "
                f"{domain_data.get('domain')}"
            )

        if domain_data.get(
            "subdomain_count",
            0
        ) >= 3:

            score += 5

            reasons.append(
                "Domain has multiple subdomains: "
                f"{domain_data.get('domain')}"
            )

    # --------------------------------
    # ATTACHMENT INTELLIGENCE
    # --------------------------------

    attachments = forensic_data.get(
        "attachments",
        []
    )

    for attachment in attachments:

        filename = attachment.get(
            "filename"
        )

        indicators = attachment.get(
            "indicators",
            {}
        )

        # Suspicious executable/script extension
        if indicators.get(
            "suspicious_extension"
        ):

            score += 20

            reasons.append(
                "Attachment uses a potentially "
                f"dangerous file extension: {filename}"
            )

        # Double extension
        if indicators.get(
            "double_extension"
        ):

            score += 25

            reasons.append(
                "Attachment uses a suspicious double "
                f"extension: {filename}"
            )

    # --------------------------------
    # RELAY ANOMALIES
    # --------------------------------

    relay_analysis = forensic_data.get(
        "relay_analysis",
        []
    )

    for hop in relay_analysis:

        anomalies = hop.get(
            "anomalies",
            []
        )

        for anomaly in anomalies:

            score += 10

            reasons.append(
                "Relay anomaly detected: "
                f"{anomaly}"
            )

    # --------------------------------
    # SCORE LIMIT
    # --------------------------------

    score = min(
        score,
        100
    )

    # --------------------------------
    # RISK LEVEL
    # --------------------------------

    if score >= 70:

        risk_level = "high"

    elif score >= 40:

        risk_level = "medium"

    else:

        risk_level = "low"

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }


if __name__ == "__main__":

    test_data = {

        "authentication": {

            "spf": "fail",

            "dkim": "fail",

            "dmarc": "fail",

            "from_domain": "example.com",

            "return_path_domain":
                "fake-security.example",

            "spf_domain":
                "fake-security.example",

            "dkim_domain":
                "fake-security.example",

            "dmarc_domain":
                "example.com",

            "alignment": {

                "spf_aligned": False,

                "dkim_aligned": False,

                "dmarc_aligned": True
            }
        },

        "sender_analysis": {

            "from_domain":
                "example.com",

            "return_path_domain":
                "fake-security.example",

            "reply_to_domain":
                "fake-security.example",

            "return_path_mismatch":
                True,

            "reply_to_mismatch":
                True
        },

        "ml_analysis": {

            "prediction":
                "phishing",

            "phishing_probability":
                0.9745
        },

        "ip_analysis": [

            {
                "ip":
                    "8.8.8.8",

                "classification":
                    "public"
            }
        ],

        "url_analysis": [

            {
                "url":
                    "http://example.com/login",

                "indicators": {

                    "uses_http":
                        True,

                    "uses_ip_address":
                        False,

                    "contains_url_encoding":
                        False
                },

                "domain_intelligence": {

                    "domain":
                        "example.com",

                    "length":
                        11,

                    "subdomain_count":
                        0,

                    "has_ip_address":
                        False,

                    "has_punycode":
                        False,

                    "has_suspicious_characters":
                        False
                }
            }
        ],

        "attachments": [

            {
                "filename":
                    "invoice.txt",

                "extension":
                    ".txt",

                "content_type":
                    "text/plain",

                "size_bytes":
                    37,

                "indicators": {

                    "suspicious_extension":
                        False,

                    "double_extension":
                        False
                }
            }
        ],

        "relay_analysis": [

            {
                "hop":
                    1,

                "anomalies":
                    []
            },

            {
                "hop":
                    2,

                "anomalies":
                    []
            }
        ]
    }

    result = calculate_threat_score(
        test_data
    )

    print(
        "=== THREAT SCORING ==="
    )

    print(
        "Score:",
        result["score"]
    )

    print(
        "Risk Level:",
        result["risk_level"]
    )

    print(
        "\nReasons:"
    )

    for reason in result["reasons"]:

        print(
            "-",
            reason
        )
