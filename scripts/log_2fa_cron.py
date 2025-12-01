# scripts/log_2fa_cron.py
#!/usr/bin/env python3

import os
import datetime
import base64
import binascii
import pyotp

SEED_FILE = "/data/seed.txt"

def generate_totp(hex_seed: str) -> str:
    seed_bytes = binascii.unhexlify(hex_seed)
    b32 = base64.b32encode(seed_bytes).decode()
    totp = pyotp.TOTP(b32, digits=6, interval=30)
    return totp.now()

def main():
    if not os.path.exists(SEED_FILE):
        print("Seed not found")
        return

    with open(SEED_FILE, "r") as f:
        hex_seed = f.read().strip()

    try:
        code = generate_totp(hex_seed)
    except Exception as e:
        print(f"Error: {e}")
        return

    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} - 2FA Code: {code}")

if __name__ == "__main__":
    main()
