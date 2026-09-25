import re
from email.utils import parsedate_to_datetime


def analyze_received_headers(received_headers):
    """
    Analyze Received headers and build a structured
    email relay chain.

    Received headers are normally stored newest first,
    so we reverse them to reconstruct the approximate
    chronological path.
    """

    hops = []

    # --------------------------------
    # CHRONOLOGICAL ORDER
    # --------------------------------

    chronological_headers = list(
        reversed(received_headers)
    )

    # Used internally for timestamp validation.
    parsed_timestamps = []

    for index, header in enumerate(
        chronological_headers,
        start=1
    ):

        # --------------------------------
        # EXTRACT IP ADDRESS
        # --------------------------------

        ip_match = re.search(
            r"\[(\d{1,3}(?:\.\d{1,3}){3})\]",
            header
        )

        ip_address = (
            ip_match.group(1)
            if ip_match
            else None
        )

        # --------------------------------
        # EXTRACT SOURCE SERVER
        # --------------------------------

        from_match = re.search(
            r"\bfrom\s+(.+?)(?:\s+\(|\s+by\s+|\s+with\s+|;)",
            header,
            re.IGNORECASE
        )

        source_server = None

        if from_match:

            source_server = (
                from_match.group(1)
                .strip()
            )

        # --------------------------------
        # EXTRACT DESTINATION SERVER
        # --------------------------------

        by_match = re.search(
            r"\bby\s+(.+?)(?:\s+with\s+|;|$)",
            header,
            re.IGNORECASE
        )

        destination_server = None

        if by_match:

            destination_server = (
                by_match.group(1)
                .strip()
            )

        # --------------------------------
        # EXTRACT PROTOCOL
        # --------------------------------

        with_match = re.search(
            r"\bwith\s+([A-Za-z0-9_-]+)",
            header,
            re.IGNORECASE
        )

        protocol = None

        if with_match:

            protocol = (
                with_match.group(1)
            )

        # --------------------------------
        # EXTRACT TIMESTAMP
        # --------------------------------

        timestamp = None

        if ";" in header:

            timestamp = (
                header.split(
                    ";",
                    1
                )[1].strip()
            )

        # --------------------------------
        # PARSE TIMESTAMP INTERNALLY
        # --------------------------------

        timestamp_datetime = None

        if timestamp:

            try:

                timestamp_datetime = (
                    parsedate_to_datetime(
                        timestamp
                    )
                )

            except (TypeError, ValueError):

                timestamp_datetime = None

        parsed_timestamps.append(
            timestamp_datetime
        )

        # --------------------------------
        # RELAY ANOMALIES
        # --------------------------------

        anomalies = []

        if not source_server:

            anomalies.append(
                "Missing source server"
            )

        if not ip_address:

            anomalies.append(
                "Missing source IP address"
            )

        if not destination_server:

            anomalies.append(
                "Missing destination server"
            )

        if not timestamp:

            anomalies.append(
                "Missing timestamp"
            )

        elif timestamp_datetime is None:

            anomalies.append(
                "Invalid timestamp format"
            )

        # --------------------------------
        # STORE HOP
        # --------------------------------

        hops.append({

            "hop": index,

            "source_server":
                source_server,

            "source_ip":
                ip_address,

            "destination_server":
                destination_server,

            "protocol":
                protocol,

            "timestamp":
                timestamp,

            "anomalies":
                anomalies,

            "raw_header":
                header
        })

    # --------------------------------
    # CHECK TIMESTAMP ORDER
    # --------------------------------

    previous_timestamp = None

    for index, current_timestamp in enumerate(
        parsed_timestamps
    ):

        if (
            previous_timestamp
            and current_timestamp
        ):

            if current_timestamp < previous_timestamp:

                hops[index][
                    "anomalies"
                ].append(
                    "Timestamp is earlier than "
                    "the previous relay hop"
                )

        if current_timestamp:

            previous_timestamp = (
                current_timestamp
            )

    # --------------------------------
    # CHECK RELAY CONTINUITY
    # --------------------------------

    for index in range(
        1,
        len(hops)
    ):

        previous_hop = hops[
            index - 1
        ]

        current_hop = hops[
            index
        ]

        previous_destination = (
            previous_hop[
                "destination_server"
            ]
        )

        current_source = (
            current_hop[
                "source_server"
            ]
        )

        # Only compare when both values
        # are available.
        if (
            previous_destination
            and current_source
        ):

            if (
                previous_destination.lower()
                != current_source.lower()
            ):

                current_hop[
                    "anomalies"
                ].append(
                    "Relay chain continuity mismatch: "
                    f"previous destination "
                    f"'{previous_destination}' does not "
                    f"match current source "
                    f"'{current_source}'"
                )

    return hops


if __name__ == "__main__":

    test_headers = [

        "from mail.fake-security.example "
        "(mail.fake-security.example [203.0.113.25]) "
        "by mail.example.com with ESMTP; "
        "Tue, 22 Sep 2026 21:29:58 +0530",

        "from unknown "
        "(unknown [198.51.100.42]) "
        "by mail.fake-security.example with ESMTP; "
        "Tue, 22 Sep 2026 21:29:55 +0530"
    ]

    result = analyze_received_headers(
        test_headers
    )

    print(
        "=== RELAY ANALYSIS ==="
    )

    for hop in result:

        print(
            "\nHop:",
            hop["hop"]
        )

        print(
            "Source:",
            hop["source_server"]
        )

        print(
            "Source IP:",
            hop["source_ip"]
        )

        print(
            "Destination:",
            hop["destination_server"]
        )

        print(
            "Protocol:",
            hop["protocol"]
        )

        print(
            "Timestamp:",
            hop["timestamp"]
        )

        print(
            "Anomalies:",
            hop["anomalies"]
        )