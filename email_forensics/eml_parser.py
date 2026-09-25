from email import policy
from email.parser import BytesParser
import re

from email_forensics.url_analyzer import (
    extract_urls,
    analyze_url,
    check_url_indicators
)

from email_forensics.attachment_analyzer import (
    extract_attachments
)

from email_forensics.authentication_analyzer import (
    analyze_authentication
)

from email_forensics.relay_analyzer import (
    analyze_received_headers
)

from email_forensics.sender_analysis import (
    analyze_sender
)

from email_forensics.forensic_result import (
    build_forensic_result
)

from threat_intelligence.ip_intelligence import (
    classify_ip
)

from threat_intelligence.ip_geolocation import (
    lookup_ip_geolocation
)

from threat_intelligence.domain_intelligence import (
    analyze_domain
)

from threat_intelligence.threat_scoring import (
    calculate_threat_score
)

from ml.email_ml_detector import (
    analyze_email_text
)


def extract_ip_addresses(text):
    """
    Extract IPv4 addresses from text.
    """

    ip_pattern = (
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    return re.findall(
        ip_pattern,
        text
    )


def extract_body(message):
    """
    Extract the plain-text body from an email.
    """

    if message.is_multipart():

        for part in message.walk():

            if (
                part.get_content_type()
                == "text/plain"
            ):
                try:
                    return part.get_content()

                except Exception:
                    return ""

    else:

        try:
            return message.get_content()

        except Exception:
            return ""

    return ""


def parse_eml(file_path):
    """
    Parse an EML file and perform
    complete forensic analysis.
    """

    # -------------------------------------------------
    # Parse EML
    # -------------------------------------------------

    with open(
        file_path,
        "rb"
    ) as file:

        message = BytesParser(
            policy=policy.default
        ).parse(file)

    # -------------------------------------------------
    # Basic email information
    # -------------------------------------------------

    sender = message.get("From")
    recipient = message.get("To")
    subject = message.get("Subject")
    date = message.get("Date")
    message_id = message.get("Message-ID")
    return_path = message.get("Return-Path")
    reply_to = message.get("Reply-To")

    # -------------------------------------------------
    # Received headers
    # -------------------------------------------------

    received_headers = message.get_all(
        "Received",
        []
    )

    received_hops = []

    for received in received_headers:

        ips = extract_ip_addresses(
            received
        )

        received_hops.append(
            {
                "header": received,
                "ip_addresses": ips
            }
        )

    # -------------------------------------------------
    # Relay analysis
    # -------------------------------------------------

    relay_analysis = analyze_received_headers(
        received_headers
    )

    # -------------------------------------------------
    # Authentication analysis
    # -------------------------------------------------

    authentication_results = message.get_all(
        "Authentication-Results",
        []
    )

    authentication = analyze_authentication(
        authentication_results,
        sender,
        return_path
    )

    # -------------------------------------------------
    # Sender analysis
    # -------------------------------------------------

    sender_analysis = analyze_sender(
        sender,
        return_path,
        reply_to
    )

    # -------------------------------------------------
    # Header IP extraction
    # -------------------------------------------------

    all_header_text = "\n".join(
        f"{name}: {value}"
        for name, value in message.items()
    )

    all_ips = sorted(
        set(
            extract_ip_addresses(
                all_header_text
            )
        )
    )

    # -------------------------------------------------
    # IP intelligence
    # -------------------------------------------------

    ip_analysis = []

    for ip in all_ips:

        classification = classify_ip(
            ip
        )

        ip_data = {
            "ip": ip,
            "classification": classification
        }

        # Only perform external
        # geolocation for public IPs.

        if classification == "public":

            geolocation = lookup_ip_geolocation(
                ip
            )

            ip_data[
                "geolocation"
            ] = geolocation

        ip_analysis.append(
            ip_data
        )

    # -------------------------------------------------
    # Email body
    # -------------------------------------------------

    body = extract_body(
        message
    )

    # -------------------------------------------------
    # Attachment analysis
    # -------------------------------------------------

    attachments = extract_attachments(
        message
    )

    # -------------------------------------------------
    # Machine learning analysis
    # -------------------------------------------------

    ml_analysis = analyze_email_text(
        body
    )

    # -------------------------------------------------
    # URL analysis
    # -------------------------------------------------

    urls = extract_urls(
        body
    )

    url_analysis = []

    for url in urls:

        url_data = analyze_url(
            url
        )

        url_data[
            "indicators"
        ] = check_url_indicators(
            url_data
        )

        domain = url_data[
            "domain"
        ]

        domain_data = analyze_domain(
            domain
        )

        url_data[
            "domain_intelligence"
        ] = domain_data

        url_analysis.append(
            url_data
        )

    # -------------------------------------------------
    # Build forensic data
    # -------------------------------------------------

    forensic_data = {

        "basic_information": {

            "from": sender,

            "to": recipient,

            "subject": subject,

            "date": date,

            "message_id": message_id,

            "return_path": return_path,

            "reply_to": reply_to
        },

        "received_hops": received_hops,

        "relay_analysis": relay_analysis,

        "authentication": authentication,

        "sender_analysis": sender_analysis,

        "ip_addresses": all_ips,

        "ip_analysis": ip_analysis,

        "body": body,

        "attachments": attachments,

        "ml_analysis": ml_analysis,

        "urls": urls,

        "url_analysis": url_analysis
    }

    # -------------------------------------------------
    # Threat scoring
    # -------------------------------------------------

    threat_assessment = calculate_threat_score(
        forensic_data
    )

    forensic_data[
        "threat_assessment"
    ] = threat_assessment

    # -------------------------------------------------
    # Final structured result
    # -------------------------------------------------

    return build_forensic_result(
        forensic_data
    )
