import requests
from pathlib import Path

API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"

# 🔴 CHANGE THIS to your real student id / roll number as required by your course
STUDENT_ID = "YOUR_STUDENT_ID_HERE"

# ✅ Use repo URL WITHOUT .git
GITHUB_REPO_URL = "https://github.com/Dakshayani2005/secure-auth-microservice"


def request_seed(student_id: str, github_repo_url: str, api_url: str):
    """
    Request encrypted seed from instructor API.
    """
    # 1. Read student public key from PEM file
    public_key_path = Path("student_public.pem")
    if not public_key_path.exists():
        raise FileNotFoundError("student_public.pem not found in project folder")

    public_key_pem = public_key_path.read_text(encoding="utf-8")

    # 2. Prepare HTTP POST request payload
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key_pem,  # newlines will be encoded as \n in JSON automatically
    }

    # 3. Send POST request
    try:
        response = requests.post(api_url, json=payload, timeout=10)
    except requests.RequestException as e:
        print(f"Error contacting instructor API: {e}")
        return

    if response.status_code != 200:
        print(f"HTTP error from API: {response.status_code}")
        print("Response text:", response.text)
        return

    # 4. Parse JSON response
    try:
        data = response.json()
    except ValueError:
        print("Failed to parse JSON response")
        print("Raw response:", response.text)
        return

    if data.get("status") != "success":
        print("API returned error:", data)
        return

    encrypted_seed = data.get("encrypted_seed")
    if not encrypted_seed:
        print("No 'encrypted_seed' field in response:", data)
        return

    # 5. Save encrypted seed to file (DO NOT COMMIT THIS FILE)
    out_path = Path("encrypted_seed.txt")
    out_path.write_text(encrypted_seed, encoding="utf-8")
    print(f"Encrypted seed saved to {out_path}")


if __name__ == "__main__":
    request_seed(STUDENT_ID, GITHUB_REPO_URL, API_URL)

