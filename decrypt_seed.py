import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Read encrypted seed
with open("encrypted_seed.txt", "r") as f:
    encrypted_seed_b64 = f.read().strip()

# Load your private key
with open("student_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# Base64 decode the encrypted seed
encrypted_seed_bytes = base64.b64decode(encrypted_seed_b64)

# Decrypt using RSA/OAEP with SHA-256
try:
    decrypted_bytes = private_key.decrypt(
        encrypted_seed_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    hex_seed = decrypted_bytes.decode("utf-8")

    # Validate 64-character hex
    if len(hex_seed) == 64 and all(c in "0123456789abcdef" for c in hex_seed.lower()):
        # Save to file (for Docker: /data/seed.txt)
        with open("seed.txt", "w") as f:
            f.write(hex_seed)
        print("Seed decrypted successfully and saved to seed.txt")
    else:
        print("Decrypted seed is invalid")
except Exception as e:
    print("Decryption failed:", e)
