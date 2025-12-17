from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import time

from decrypt_seed import load_private_key, decrypt_seed
from totp_utils import generate_totp_code, verify_totp_code

app = FastAPI()

DATA_DIR = Path("./data")
SEED_FILE = DATA_DIR / "seed.txt"

# Ensure directory exists (for local testing)
DATA_DIR.mkdir(exist_ok=True)


# ----------------------------
# Endpoint 1: POST /decrypt-seed
# ----------------------------
class EncryptedSeedRequest(BaseModel):
    encrypted_seed: str


@app.post("/decrypt-seed")
def decrypt_seed_endpoint(req: EncryptedSeedRequest):
    try:
        private_key = load_private_key("student_private.pem")

        hex_seed = decrypt_seed(req.encrypted_seed, private_key)

        # Save seed into /data/seed.txt
        SEED_FILE.write_text(hex_seed, encoding="utf-8")

        return {"status": "ok"}

    except Exception as e:
        raise HTTPException(status_code=500, detail="Decryption failed")


# ----------------------------
# Endpoint 2: GET /generate-2fa
# ----------------------------
@app.get("/generate-2fa")
def generate_2fa():
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    try:
        hex_seed = SEED_FILE.read_text().strip()

        code = generate_totp_code(hex_seed)

        # Calculate remaining seconds in 30-second TOTP period
        now = int(time.time())
        valid_for = 30 - (now % 30)

        return {
            "code": code,
            "valid_for": valid_for
        }

    except Exception:
        raise HTTPException(status_code=500, detail="TOTP generation failed")


# ----------------------------
# Endpoint 3: POST /verify-2fa
# ----------------------------
class VerifyCodeRequest(BaseModel):
    code: str | None = None


@app.post("/verify-2fa")
def verify_2fa(req: VerifyCodeRequest):
    if req.code is None:
        raise HTTPException(status_code=400, detail="Missing code")

    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    try:
        hex_seed = SEED_FILE.read_text().strip()

        is_valid = verify_totp_code(hex_seed, req.code, valid_window=1)

        return {"valid": is_valid}

    except Exception:
        raise HTTPException(status_code=500, detail="Verification error")

