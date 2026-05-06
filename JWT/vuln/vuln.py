import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# LỖ HỔNG 1: Secret Key quá yếu và dễ đoán (Weak Secret)
SECRET_KEY = "123456"

# Giả sử có một user bình thường
USERS = {"guest": "guestpass"}

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if USERS.get(username) == password:
        # LỖ HỔNG 2: Không set thời gian hết hạn (Token này sống mãi mãi)
        payload = {
            "sub": username,
            "role": "user" # Role chỉ là user thường
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return jsonify({"access_token": token})
        
    return jsonify({"error": "Unauthorized"}), 401

@app.route('/admin-dashboard')
def admin_dashboard():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Unauthorized"}), 401
        
    token = auth_header.split(' ')[1]
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        # Server chỉ tin tưởng vào role nằm trong Payload
        if payload.get("role") != "admin":
            return jsonify({"error": "Access Denied. Admins only."}), 403
            
        return jsonify({"message": f"Hello Admin {payload.get('sub')}", "data": "Server compromised."})
    except:
        return jsonify({"error": "Invalid Token"}), 401

if __name__ == '__main__':
    print("[*] Vulnerable JWT Server running on port 5001")
    app.run(port=5001)
