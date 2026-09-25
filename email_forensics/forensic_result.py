def build_forensic_result(forensic_data):
    """
    Build a clean, backend-friendly forensic result.

    This function reorganizes the existing forensic data
    into logical sections without changing the analysis.
    """

    basic_information = forensic_data.get(
        "basic_information",
        {}
    )

    authentication = forensic_data.get(
        "authentication",
        {}
    )

    sender_analysis = forensic_data.get(
        "sender_analysis",
        {}
    )

    relay_analysis = forensic_data.get(
        "relay_analysis",
        []
    )

    ip_analysis = forensic_data.get(
        "ip_analysis",
        []
    )

    url_analysis = forensic_data.get(
        "url_analysis",
        []
    )

    attachments = forensic_data.get(
        "attachments",
        []
    )

    ml_analysis = forensic_data.get(
        "ml_analysis",
        {}
    )

    threat_assessment = forensic_data.get(
        "threat_assessment",
        {}
    )

    return {

        # --------------------------------
        # EMAIL
        # --------------------------------

        "email": {

            "from":
                basic_information.get(
                    "from"
                ),

            "to":
                basic_information.get(
                    "to"
                ),

            "subject":
                basic_information.get(
                    "subject"
                ),

            "date":
                basic_information.get(
                    "date"
                ),

            "message_id":
                basic_information.get(
                    "message_id"
                ),

            "return_path":
                basic_information.get(
                    "return_path"
                ),

            "reply_to":
                basic_information.get(
                    "reply_to"
                )
        },

        # --------------------------------
        # AUTHENTICATION
        # --------------------------------

        "authentication":
            authentication,

        # --------------------------------
        # SENDER ANALYSIS
        # --------------------------------

        "sender_analysis":
            sender_analysis,

        # --------------------------------
        # RELAY
        # --------------------------------

        "relay": {

            "hop_count":
                len(relay_analysis),

            "hops":
                relay_analysis,

            "anomaly_count":
                sum(
                    len(
                        hop.get(
                            "anomalies",
                            []
                        )
                    )
                    for hop in relay_analysis
                )
        },

        # --------------------------------
        # IP INTELLIGENCE
        # --------------------------------

        "ip_intelligence": {

            "ip_count":
                len(ip_analysis),

            "ips":
                ip_analysis
        },

        # --------------------------------
        # URL INTELLIGENCE
        # --------------------------------

        "url_intelligence": {

            "url_count":
                len(url_analysis),

            "urls":
                url_analysis
        },

        # --------------------------------
        # ATTACHMENTS
        # --------------------------------

        "attachments": {

            "attachment_count":
                len(attachments),

            "files":
                attachments
        },

        # --------------------------------
        # MACHINE LEARNING
        # --------------------------------

        "ml": {

            "prediction":
                ml_analysis.get(
                    "prediction"
                ),

            "phishing_probability":
                ml_analysis.get(
                    "phishing_probability",
                    0.0
                )
        },

        # --------------------------------
        # THREAT ASSESSMENT
        # --------------------------------

        "threat_assessment":
            threat_assessment
    }


if __name__ == "__main__":

    print(
        "=== FORENSIC RESULT FORMATTER ==="
    )

    print(
        "Forensic result formatter loaded successfully."
    )
