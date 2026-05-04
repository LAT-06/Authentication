from flask import Flask, request, jsonify

app = Flask(__name__)

# LỖ HỔNG 1: Lưu password dưới dạng plaintext
USERS = {
    "admin": "password123",
    "test": "123456"
}

@app.route('/data')
def get_data():
    auth = request.authorization
    
    # LỖ HỔNG 2: Không có Rate Limiting (Cho phép Brute-force vô hạn)
    # LỖ HỔNG 3: Không ép buộc HTTPS (Chạy HTTP trần)
    if not auth or USERS.get(auth.username) != auth.password:
        # Đã thêm header WWW-Authenticate
        return jsonify({"error": "Unauthorized"}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}
    
    return jsonify({"message": "Successfully", "data": "Data leaked!"})

if __name__ == '__main__':
    app.run(port=5001)
