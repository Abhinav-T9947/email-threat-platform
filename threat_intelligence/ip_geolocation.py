import json
import urllib.parse
import urllib.request


def lookup_ip_geolocation(ip):
    """
    Look up approximate geolocation and network information
    for a public IP address using ipapi.is.
    """

    encoded_ip = urllib.parse.quote(ip, safe="")
    url = f"https://api.ipapi.is/?q={encoded_ip}"

    try:

        with urllib.request.urlopen(
            url,
            timeout=5
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

        return {
            "ip": ip,
            "success": True,
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "isp": data.get("company"),
            "organization": data.get("company"),
            "asn": data.get("asn"),
            "timezone": data.get("timezone"),
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