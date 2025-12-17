from pathlib import Path
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def load_private_key(path: str = "student_private.pem"):
    """
    Load the RSA private key from a PEM file.
    Assumes the key is not password-protected.
    """
    pem_path = Path(path)
    if not pem_path.exists():
        raise FileNotFoundError(f"Private key file not found: {path}")

    pem_data = pem_path.read_bytes()

    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None,  # key is not encrypted
    )
    return private_key


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP (SHA-256).

    Args:
        encrypted_seed_b64: Base64-encoded ciphertext
        private_key: RSA private key object

    Returns:
        Decrypted hex seed (64-character string)
    """
    # 1. Base64 decode the encrypted seed string
    try:
        ciphertext = base64.b64decode(encrypted_seed_b64, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid base64 encrypted seed: {e}")

    # 2. RSA/OAEP decrypt with SHA-256, MGF1(SHA-256), label=None
    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        # In the API + service we’ll convert this to a clean error JSON
        raise ValueError(f"Decryption failed: {e}")

    # 3. Decode bytes to UTF-8 string
    try:
        seed_str = plaintext_bytes.decode("utf-8").strip()
    except UnicodeDecodeError as e:
        raise ValueError(f"Decrypted bytes are not valid UTF-8: {e}")

    # 4. Validate: must be 64-character lowercase hex string
    if len(seed_str) != 64:
        raise ValueError(f"Decrypted seed must be 64 characters, got {len(seed_str)}")

    allowed_chars = set("0123456789abcdef")
    if not all(ch in allowed_chars for ch in seed_str):
        raise ValueError(
            "Decrypted seed must be a lowercase hex string (0-9, a-f only)"
        )

    # 5. Return hex seed
    return seed_str


def main():
    # Read encrypted seed from file
    encrypted_path = Path("encrypted_seed.txt")
    if not encrypted_path.exists():
        raise FileNotFoundError("encrypted_seed.txt not found. Run request_seed.py first.")

    encrypted_seed_b64 = encrypted_path.read_text(encoding="utf-8").strip()

    # Load private key
    private_key = load_private_key("student_private.pem")

    # Decrypt
    hex_seed = decrypt_seed(encrypted_seed_b64, private_key)
    print("Decrypted seed (hex):", hex_seed)

    # Save decrypted seed for later (this will correspond to /data/seed.txt in Docker)
    seed_out_path = Path("seed.txt")
    seed_out_path.write_text(hex_seed, encoding="utf-8")
    print(f"Decrypted seed saved to {seed_out_path}")


if __name__ == "__main__":
    main()

