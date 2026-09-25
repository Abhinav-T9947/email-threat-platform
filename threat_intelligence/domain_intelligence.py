from urllib.parse import urlparse
import re


def analyze_domain(domain):
    """
    Analyze basic characteristics of a domain.
    """

    if not domain:
        return {
            "domain": domain,
            "length": 0,
            "subdomain_count": 0,
            "has_ip_address": False,
            "has_punycode": False,
            "has_suspicious_characters": False
        }

    # Check whether the domain is an IPv4 address
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    has_ip_address = bool(re.match(ip_pattern, domain))

    # Split domain into parts
    parts = domain.split(".")

    # Number of subdomains
    # example:
    # login.security.example.com
    # login + security = 2 subdomains
    subdomain_count = max(len(parts) - 2, 0)

    # Punycode domains start with xn--
    has_punycode = any(
        part.lower().startswith("xn--")
        for part in parts
    )

    # Look for unusual characters
    suspicious_character_pattern = r"[^a-zA-Z0-9.\-]"

    has_suspicious_characters = bool(
        re.search(
            suspicious_character_pattern,
            domain
        )
    )

    return {
        "domain": domain,
        "length": len(domain),
        "subdomain_count": subdomain_count,
        "has_ip_address": has_ip_address,
        "has_punycode": has_punycode,
        "has_suspicious_characters": has_suspicious_characters
    }


if __name__ == "__main__":

    test_domains = [
        "example.com",
        "login.example.com",
        "secure.login.example.com",
        "192.0.2.10",
        "xn--example-dk9c.com"
    ]

    print("=== DOMAIN INTELLIGENCE ===")

    for domain in test_domains:

        result = analyze_domain(domain)

        print("\nDomain:", domain)

        for key, value in result.items():
            print(f"{key}: {value}")