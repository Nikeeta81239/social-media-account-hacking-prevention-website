import requests

def get_location(ip_address):
    """
    Returns country, region, city based on IP address
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()

        if data["status"] == "success":
            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "ip": ip_address
            }
        else:
            return {
                "country": "Unknown",
                "region": "Unknown",
                "city": "Unknown",
                "ip": ip_address
            }

    except Exception as e:
        return {
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "ip": ip_address
        }
