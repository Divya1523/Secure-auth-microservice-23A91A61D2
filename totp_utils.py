import base64
import pyotp


def hex_to_base32(hex_seed: str) -> str:
    """
    Convert 64-character hex seed to base32-encoded string.
    """
    # Convert hex → bytes
    seed_bytes = bytes.fromhex(hex_seed)

    # Convert bytes → base32 (gives bytes)
    seed_b32_bytes = base64.b32encode(seed_bytes)

    # Convert bytes → string
    return seed_b32_bytes.decode("utf-8")


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code from hex seed.
    """
    # 1. Convert hex → base32
    seed_b32 = hex_to_base32(hex_seed)

    # 2. Create TOTP generator using SHA-1, 30s timer, 6 digits (default)
    totp = pyotp.TOTP(seed_b32, digits=6, interval=30)  # SHA-1 is default

    # 3. Generate current OTP
    code = totp.now()  # Returns 6-digit string

    return code


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with ±30 second tolerance.
    """
    # 1. Convert hex → base32
    seed_b32 = hex_to_base32(hex_seed)

    # 2. Create TOTP validator
    totp = pyotp.TOTP(seed_b32, digits=6, interval=30)  # SHA-1 default

    # 3. Verify with window tolerance (±1 = ±30 seconds)
    return totp.verify(code, valid_window=valid_window)

