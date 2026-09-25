import json
import urllib.request


def lookup_ip_geolocation(ip):
    """
    Look up approximate geolocation and network information
    for a public IP address.

    This uses ip-api.com's free HTTP endpoint for development.
    """

    url = f"http://ip-api.com/json/{ip}"

    try:

        with urllib.request.urlopen(
            url,
            timeout=5
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

        if data.get("status") != "success":

            return {
                "ip": ip,
                "success": False,
                "error": data.get(
                    "message",
                    "Lookup failed"
                )
            }

        return {
            "ip": ip,
            "success": True,
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "isp": data.get("isp"),
            "organization": data.get("org"),
            "asn": data.get("as"),
        }

    except Exception as error:

        return {
            "ip": ip,
            "success": False,
            "error": str(error)
        }


if __name__ == "__main__":

    test_ip = "8.8.8.8"

    print(
        "=== IP GEOLOCATION ==="
    )

    result = lookup_ip_geolocation(
        test_ip
    )

    print(
        json.dumps(
            result,
            indent=4
        )
    )