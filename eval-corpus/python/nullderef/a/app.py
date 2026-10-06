import json


def user_city(payload: str) -> str:
    """Return the city from a JSON user record.

    VULNERABLE: the 'address' field is assumed to be present. When it is missing,
    data.get('address') returns None and the attribute access on None raises
    AttributeError (CWE-476 / CWE-690: unchecked None from external input).
    """
    data = json.loads(payload)
    address = data.get("address")
    return address.get("city", "unknown")
