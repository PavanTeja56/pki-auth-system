from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64
from .utils import generate_totp_code, verify_totp_code

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

app = FastAPI()

SEED_FILE = "seed.txt"
PRIVATE_KEY_FILE = "student_private.pem"

# Request body model for decrypt-seed
class DecryptSeedRequest(BaseModel):
    encrypted_seed: str

# Request body model for verify-2fa
class Verify2FARequest(BaseModel):
    code: str

@app.get("/")
def home():
    return {"message": "Server is running"}

@app.post("/decrypt-seed")
def decrypt_seed(data: DecryptSeedRequest):
    try:
        # Load private key
        with open(PRIVATE_KEY_FILE, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        # Decode encrypted seed from base64
        encrypted_bytes = base64.b64decode(data.encrypted_seed)
        # Decrypt using RSA/OAEP-SHA256
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Save decrypted seed (hex) to seed.txt
        with open(SEED_FILE, "wb") as f:
            f.write(decrypted)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Decryption failed")

@app.get("/generate-2fa")
def generate_2fa():
    if not os.path.exists(SEED_FILE):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    with open(SEED_FILE, "rb") as f:
        hex_seed = f.read().strip().decode()
    code = generate_totp_code(hex_seed)
    return {"code": code, "valid_for": 30}

@app.post("/verify-2fa")
def verify_2fa(data: Verify2FARequest):
    if not os.path.exists(SEED_FILE):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    with open(SEED_FILE, "rb") as f:
        hex_seed = f.read().strip().decode()
    valid = verify_totp_code(hex_seed, data.code)
    return {"valid": valid}
