# test_totp.py
from app.utils import generate_totp_code, verify_totp_code

with open("seed.txt","r") as f:
    hex_seed = f.read().strip()

print("Hex seed length:", len(hex_seed))
code = generate_totp_code(hex_seed)
print("Current TOTP code:", code)

# verify immediately (should be True)
print("Verify immediate:", verify_totp_code(hex_seed, code))
