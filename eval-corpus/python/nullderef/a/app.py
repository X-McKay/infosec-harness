import json


def user_city(payload: str) -> str:
    """Return the city from a JSON user record."""
    data = json.loads(payload)
    address = data.get("address")
    return address.get("city", "unknown")
