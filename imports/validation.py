def is_valid_ip_address(ip_address):
    """Check if the given string is a valid IP address."""
    parts = ip_address.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True