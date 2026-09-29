def make_header(value: str) -> str:
    if "\r" in value or "\n" in value:
        raise ValueError("line breaks are forbidden")
    return f"X-Display: {value}"
