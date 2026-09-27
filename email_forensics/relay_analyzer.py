import re
from email.utils import parsedate_to_datetime


def analyze_received_headers(received_headers):
    """
    Analyze Received headers and build an approximate relay chain.

    Received headers are normally stored newest first, so reverse them
    to reconstruct the approximate chronological path.

    Some legitimate Received headers omit a source server or IP.
    Those omissions are recorded as missing data, not anomalies
    by themselves.
    """
    hops = []
    chronological_headers = list(reversed(received_headers))
    parsed_timestamps = []

    for index, header in enumerate(chronological_headers, start=1):

        # --------------------------------
        # EXTRACT SOURCE IP ADDRESS
        # --------------------------------

        ip_match = re.search(
            r"\[(\d{1,3}(?:\.\d{1,3}){3})\]",
            header
        )

        ip_address = ip_match.group(1) if ip_match else None

        # --------------------------------
        # EXTRACT SOURCE SERVER
        # --------------------------------

        from_match = re.search(
            r"\bfrom\s+(.+?)(?:\s+\(|\s+by\s+|\s+with\s+|;)",
            header,
            re.IGNORECASE
        )

        source_server = (
            from_match.group(1).strip()
            if from_match
            else None
        )

        # --------------------------------
        # EXTRACT DESTINATION SERVER
        # --------------------------------

        by_match = re.search(
            r"\bby\s+(.+?)(?:\s+with\s+|;|$)",
            header,
            re.IGNORECASE
        )

        destination_server = (
            by_match.group(1).strip()
            if by_match
            else None
        )

        # --------------------------------
        # EXTRACT PROTOCOL
        # --------------------------------

        with_match = re.search(
            r"\bwith\s+([A-Za-z0-9_-]+)",
            header,
            re.IGNORECASE
        )

        protocol = (
            with_match.group(1)
            if with_match
            else None
        )

        # --------------------------------
        # EXTRACT TIMESTAMP
        # --------------------------------

        timestamp = None

        if ";" in header:
            timestamp = header.split(";", 1)[1].strip()

        # --------------------------------
        # PARSE TIMESTAMP INTERNALLY
        # --------------------------------

        timestamp_datetime = None

        if timestamp:
            try:
                timestamp_datetime = parsedate_to_datetime(timestamp)
            except (TypeError, ValueError, OverflowError):
                timestamp_datetime = None

        parsed_timestamps.append(timestamp_datetime)

        # --------------------------------
        # RELAY ANOMALIES
        # --------------------------------

        anomalies = []

        # Missing source server/IP are not anomalies by themselves.
        # Some legitimate Received headers do not include these fields.

        if not destination_server:
            anomalies.append("Missing destination server")

        if not timestamp:
            anomalies.append("Missing timestamp")

        elif timestamp_datetime is None:
            anomalies.append("Invalid timestamp format")

        # --------------------------------
        # STORE HOP
        # --------------------------------

        hops.append({
            "hop": index,
            "source_server": source_server,
            "source_ip": ip_address,
            "destination_server": destination_server,
            "protocol": protocol,
            "timestamp": timestamp,
            "anomalies": anomalies,
            "raw_header": header
        })

    # --------------------------------
    # CHECK TIMESTAMP ORDER
    # --------------------------------

    previous_timestamp = None

    for index, current_timestamp in enumerate(parsed_timestamps):

        if previous_timestamp and current_timestamp:
            try:
                if current_timestamp < previous_timestamp:
                    hops[index]["anomalies"].append(
                        "Timestamp is earlier than the previous relay hop"
                    )

            except TypeError:
                # Avoid comparing incompatible timezone-aware/naive values.
                hops[index]["anomalies"].append(
                    "Timestamp timezone could not be compared"
                )

        if current_timestamp:
            previous_timestamp = current_timestamp

    # --------------------------------
    # CHECK RELAY CONTINUITY
    # --------------------------------

    for index in range(1, len(hops)):

        previous_hop = hops[index - 1]
        current_hop = hops[index]

        previous_destination = previous_hop["destination_server"]
        current_source = current_hop["source_server"]

        # Compare only when both values are available.
        if previous_destination and current_source:

            if previous_destination.lower() != current_source.lower():
                current_hop["anomalies"].append(
                    "Relay chain continuity mismatch: "
                    f"previous destination '{previous_destination}' does not "
                    f"match current source '{current_source}'"
                )

    return hops


if __name__ == "__main__":

    # Received headers are supplied newest first.
    # The analyzer reverses them to reconstruct chronological order.
    test_headers = [
        (
            "by mx.example.com with SMTP id example123; "
            "Tue, 22 Sep 2026 21:30:00 +0530"
        ),
        (
            "from mail.fake-security.example "
            "(mail.fake-security.example [203.0.113.25]) "
            "by mail.example.com with ESMTP; "
            "Tue, 22 Sep 2026 21:29:58 +0530"
        ),
        (
            "from unknown "
            "(unknown [198.51.100.42]) "
            "by mail.fake-security.example with ESMTP; "
            "Tue, 22 Sep 2026 21:29:55 +0530"
        )
    ]

    result = analyze_received_headers(test_headers)

    print("=== RELAY ANALYSIS ===")

    for hop in result:
        print(f"\nHop: {hop['hop']}")
        print("Source:", hop["source_server"])
        print("Source IP:", hop["source_ip"])
        print("Destination:", hop["destination_server"])
        print("Protocol:", hop["protocol"])
        print("Timestamp:", hop["timestamp"])
        print("Anomalies:", hop["anomalies"])