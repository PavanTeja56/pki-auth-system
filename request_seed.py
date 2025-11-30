import requests
import json

STUDENT_ID = "23A91A4457"  # Replace with your actual student ID
GITHUB_REPO_URL = "https://github.com/PavanTeja56/pki-auth-system"  # Your repo URL
API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws/"

# Read student public key
with open("student_public.pem", "r") as f:
    public_key = f.read()

# Prepare payload
payload = {
    "student_id": STUDENT_ID,
    "github_repo_url": GITHUB_REPO_URL,
    "public_key": public_key
}

# Send POST request
response = requests.post(API_URL, json=payload)
data = response.json()

# Check and save encrypted seed
if data.get("status") == "success":
    encrypted_seed = data.get("encrypted_seed")
    with open("encrypted_seed.txt", "w") as f:
        f.write(encrypted_seed)
    print("Encrypted seed saved to encrypted_seed.txt")
else:
    print("Error requesting seed:", data)
