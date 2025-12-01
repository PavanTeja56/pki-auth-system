# app/utils.py
import base64
import binascii
import pyotp

def generate_totp_code(hex_seed: str) -> str:

    """
    Convert 64-char hex seed -> base32 -> generate 6-digit TOTP (SHA-1, 30s)
    Returns 6-digit string.
    """
    if not hex_seed or len(hex_seed) != 64:
        raise ValueError("hex_seed must be a 64-character hex string")

    try:
        seed_bytes = binascii.unhexlify(hex_seed)
    except (binascii.Error, TypeError) as e:
        raise ValueError("Invalid hex seed") from e

    b32 = base64.b32encode(seed_bytes).decode("utf-8")
    totp = pyotp.TOTP(b32, digits=6, interval=30, digest='sha1')
    return totp.now()

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a 6-digit TOTP code using ±valid_window periods (default 1 => ±30s).
    Returns True if valid, False otherwise.
    """
    if not code or not code.isdigit() or len(code) != 6:
        return False

    try:
        seed_bytes = binascii.unhexlify(hex_seed)
    except (binascii.Error, TypeError):
        raise ValueError("Invalid hex seed")

    b32 = base64.b32encode(seed_bytes).decode("utf-8")
    totp = pyotp.TOTP(b32, digits=6, interval=30, digest='sha1')
    return bool(totp.verify(code, valid_window=valid_window))
