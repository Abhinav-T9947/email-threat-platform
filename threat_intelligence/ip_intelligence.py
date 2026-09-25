import ipaddress


def classify_ip(ip):
    """
    Classify an IPv4 or IPv6 address.
    """

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"

    # Loopback addresses
    if address.is_loopback:
        return "loopback"

    # Link-local addresses
    if address.is_link_local:
        return "link-local"

    # Documentation/test networks
    documentation_networks = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32")
    ]

    for network in documentation_networks:

        if address in network:
            return "documentation"

    # Private addresses
    if address.is_private:
        return "private"

    # Multicast addresses
    if address.is_multicast:
        return "multicast"

    # Reserved addresses
    if address.is_reserved:
        return "reserved"

    # Unspecified addresses
    if address.is_unspecified:
        return "unspecified"

    # Everything else
    return "public"


if __name__ == "__main__":

    test_ips = [
        "192.168.1.10",
        "127.0.0.1",
        "169.254.1.10",
        "8.8.8.8",
        "203.0.113.25",
        "198.51.100.42",
        "192.0.2.10"
    ]

    print("=== IP INTELLIGENCE ===")

    for ip in test_ips:

        classification = classify_ip(ip)

        print(
            f"{ip} -> {classification}"
        )