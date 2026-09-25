import re
from urllib.parse import urlparse


def extract_urls(text):
    url_pattern = r"https?://[^\s<>\"']+"

    urls = re.findall(
        url_pattern,
        text
    )

    return sorted(set(urls))


def analyze_url(url):
    parsed = urlparse(url)

    domain = parsed.hostname

    return {
        "url": url,
        "scheme": parsed.scheme,
        "domain": domain,
        "path": parsed.path
    }


def is_ip_address(domain):
    if not domain:
        return False

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    return bool(
        re.match(
            ip_pattern,
            domain
        )
    )


def has_url_encoding(url):
    return bool(
        re.search(
            r"%[0-9A-Fa-f]{2}",
            url
        )
    )


def has_punycode(domain):
    if not domain:
        return False

    parts = domain.split(".")

    return any(
        part.lower().startswith("xn--")
        for part in parts
    )


def is_long_domain(domain):
    if not domain:
        return False

    return len(domain) > 50


def has_many_subdomains(domain):
    if not domain:
        return False

    parts = domain.split(".")

    subdomain_count = max(
        len(parts) - 2,
        0
    )

    return subdomain_count >= 3


def has_suspicious_characters(domain):
    if not domain:
        return False

    suspicious_pattern = r"[^a-zA-Z0-9.\-]"

    return bool(
        re.search(
            suspicious_pattern,
            domain
        )
    )


def check_url_indicators(url_data):

    domain = url_data["domain"]

    indicators = {
        "uses_http": (
            url_data["scheme"].lower()
            == "http"
        ),

        "uses_ip_address": is_ip_address(
            domain
        ),

        "contains_url_encoding": has_url_encoding(
            url_data["url"]
        ),

        "has_punycode": has_punycode(
            domain
        ),

        "long_domain": is_long_domain(
            domain
        ),

        "many_subdomains": has_many_subdomains(
            domain
        ),

        "suspicious_characters": has_suspicious_characters(
            domain
        )
    }

    return indicators


if __name__ == "__main__":

    test_urls = [
        "http://192.0.2.10/login",
        "http://example.com/verify",
        "https://example.com/login?user%3Dadmin",
        "https://example.org/login",
        "https://xn--pple-43d.example/login",
        "https://sub.one.two.example.com/login",
        "https://this-is-a-very-long-domain-name-that-should-trigger-the-domain-length-check.example/login"
    ]

    print("=== URL ANALYSIS ===")

    for url in test_urls:

        url_data = analyze_url(url)

        indicators = check_url_indicators(
            url_data
        )

        print()
        print("URL:", url)
        print(
            "Scheme:",
            url_data["scheme"]
        )
        print(
            "Domain:",
            url_data["domain"]
        )
        print(
            "Path:",
            url_data["path"]
        )
        print(
            "Indicators:",
            indicators
        )