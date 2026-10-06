import json


def user_city(payload: str) -> str:
    """Return the city from a JSON user record.

    FIXED: the 'address' field is validated before it is dereferenced. A missing
    or non-object address falls back to a default instead of faulting.
    """
    data = json.loads(payload)
    address = data.get("address")
    if not isinstance(address, dict):
        return "unknown"
    return address.get("city", "unknown")
