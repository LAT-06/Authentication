import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

USERS = {"admin": "password123"}
TOKENS = {}

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    
    if USERS.get(username) == data.get('password'):
        # LỖ HỔNG 1: Token là giá trị hash MD5 của chính username. Hoàn toàn không có tính ngẫu nhiên.
        token = hashlib.md5(username.encode()).hexdigest()
        TOKENS[token] = username
        
        return jsonify({"access_token": token})
        
    return jsonify({"error": "Unauthorized"}), 401

@app.route('/api/data')
def get_data():
    # LỖ HỔNG 2: Nhận token trực tiếp từ URL query parameter (ví dụ: /api/data?token=abc).
    # Việc này cực kỳ nguy hiểm vì token sẽ bị lưu lại toàn bộ trong access.log của server.
    token = request.args.get('token')
    
    if not token or token not in TOKENS:
        return jsonify({"error": "Unauthorized"}), 401
        
    user = TOKENS.get(token)
    return jsonify({"message": f"Hello {user}", "data": "Server compromised."})

if __name__ == '__main__':
    print("[*] Vulnerable Token Server running on port 5001")
    app.run(port=5001)
