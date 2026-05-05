import secrets
import hmac
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Áp dụng SRP: Chuyên xử lý logic sinh token an toàn
class TokenGenerator:
    @staticmethod
    def generate() -> str:
        # BẬT TÍNH NĂNG NÀY: Dùng thư viện secrets của hệ điều hành để sinh token ngẫu nhiên an toàn về mặt mật mã.
        # NẾU KHÔNG BẬT: Dùng random thông thường (pseudo-random) có thể bị attacker đoán được seed và sinh ra token hợp lệ.
        return secrets.token_urlsafe(32)

# Áp dụng SRP & OCP: Kho lưu trữ Token (có thể mở rộng thành RedisStore sau này)
class TokenStore:
    def __init__(self):
        self._tokens = {}
        
    def save(self, token: str, username: str):
        self._tokens[token] = username
        
    def get_user(self, provided_token: str):
        # BẬT TÍNH NĂNG NÀY: Dùng hmac.compare_digest để so sánh token.
        # NẾU KHÔNG BẬT: Dùng `==` sẽ dừng lại ngay khi có 1 ký tự sai, attacker có thể đo thời gian phản hồi (Timing Attack) để dò từng ký tự của token thật.
        for stored_token, user in self._tokens.items():
            if hmac.compare_digest(stored_token, provided_token):
                return user
        return None

class UserRepository:
    def __init__(self):
        self._users = {"admin": generate_password_hash("SuperSecret123")}
        
    def verify(self, username, password):
        user_hash = self._users.get(username)
        return check_password_hash(user_hash, password) if user_hash else False

user_repo = UserRepository()
token_store = TokenStore()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or not user_repo.verify(data.get('username'), data.get('password')):
        return jsonify({"error": "Unauthorized"}), 401
    
    token = TokenGenerator.generate()
    token_store.save(token, data['username'])
    
    # Trả token về cho client để client tự quản lý (Lưu ở LocalStorage/Secure Storage)
    return jsonify({"access_token": token, "token_type": "Bearer"})

@app.route('/api/data')
def get_data():
    # BẬT TÍNH NĂNG NÀY: Yêu cầu token phải nằm trong Header Authorization.
    # NẾU KHÔNG BẬT: Cho phép gửi token qua URL (GET params) sẽ làm lộ token vào file log của Web Server (như Nginx, Apache).
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Unauthorized"}), 401
        
    token = auth_header.split(' ')[1]
    user = token_store.get_user(token)
    
    if not user:
        return jsonify({"error": "Invalid Token"}), 401
        
    return jsonify({"message": f"Hello {user}", "data": "Confidential data."})

if __name__ == '__main__':
    print("[*] Secure Token Auth Server running on port 5000")
    app.run(port=5000)
