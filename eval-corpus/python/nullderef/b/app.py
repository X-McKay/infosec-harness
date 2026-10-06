import json


def user_city(payload: str) -> str:
    """Return the city from a JSON user record."""
    data = json.loads(payload)
    if not isinstance(data, dict):
        return "unknown"
    address = data.get("address")
    if not isinstance(address, dict):
        return "unknown"
    return address.get("city", "unknown")
