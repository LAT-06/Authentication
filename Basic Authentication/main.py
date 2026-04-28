import base64
import hmac
from flask import Flask, request, Response

app = Flask(__name__)

# Giả lập Database (plaintext chỉ để demo)
USERS_DB = {
    "admin": "123"
}

def safe_compare(val1: str, val2: str) -> bool:
    """
    So sánh constant-time để tránh timing attack.
    Luôn nhận vào string (không bao giờ None).
    """
    return hmac.compare_digest(val1.encode('utf-8'), val2.encode('utf-8'))

def require_basic_auth():
    """
    Trả về 401 + header chuẩn để trigger browser popup.
    """
    return Response(
        "Unauthorized Access\n",
        401,
        {"WWW-Authenticate": 'Basic realm="Restricted_Zone"'}
    )

def extract_and_verify(auth_header: str) -> bool:
    """
    Decode + verify credentials.
    Không bao giờ để None đi vào compare.
    """
    try:
        # "Basic base64string"
        parts = auth_header.split(" ", 1)
        if len(parts) != 2:
            return False

        encoded_credentials = parts[1]
        decoded_bytes = base64.b64decode(encoded_credentials)
        decoded_string = decoded_bytes.decode("utf-8")

        # username:password
        username, password = decoded_string.split(":", 1)

        # Nếu user không tồn tại → dùng empty string để giữ timing gần giống
        expected_password = USERS_DB.get(username, "")

        return safe_compare(password, expected_password)

    except Exception:
        return False

@app.route("/dashboard")
def dashboard():
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Basic "):
        return require_basic_auth()

    if extract_and_verify(auth_header):
        return "Welcome to the Dashboard!"
    else:
        return require_basic_auth()

if __name__ == "__main__":
    app.run(port=5000, debug=True)
