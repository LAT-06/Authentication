import jwt
import datetime
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# BẬT TÍNH NĂNG NÀY: Secret Key phải dài, phức tạp và được bảo mật tuyệt đối (thường lấy từ biến môi trường .env)
# NẾU KHÔNG BẬT: Attacker có thể bẻ khóa thuật toán HS256 để tự tạo JWT giả.
SECRET_KEY = "your_mom_weight_150kg_is_a_strong_secret_key"

# Áp dụng SRP: Quản lý vòng đời và xác thực JWT
class JWTService:
    def __init__(self, secret: str):
        self.secret = secret
        self.algorithm = "HS256"

    def generate_token(self, username: str, role: str) -> str:
        # BẬT TÍNH NĂNG NÀY: Luôn phải có 'exp' (Expiration Time) để token tự hủy sau một khoảng thời gian.
        payload = {
            "sub": username,
            "role": role,
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15) # Hết hạn sau 15 phút
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def decode_token(self, token: str) -> dict:
        try:
            # Tham số algorithms=[self.algorithm] cực kỳ quan trọng để chặn lỗi 'none' algorithm
            return jwt.decode(token, self.secret, algorithms=[self.algorithm])
        except jwt.ExpiredSignatureError:
            return {"error": "Token has expired"}
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}

class UserRepository:
    def __init__(self):
        self._users = {"admin": generate_password_hash("SuperSecret123")}
        
    def verify(self, username, password):
        user_hash = self._users.get(username)
        return check_password_hash(user_hash, password) if user_hash else False

jwt_service = JWTService(SECRET_KEY)
user_repo = UserRepository()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or not user_repo.verify(data.get('username'), data.get('password')):
        return jsonify({"error": "Unauthorized"}), 401
    
    # Cấp token chứa thông tin user và role
    token = jwt_service.generate_token(data['username'], role="admin")
    return jsonify({"access_token": token, "token_type": "Bearer"})

@app.route('/admin-dashboard')
def admin_dashboard():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Unauthorized"}), 401
        
    token = auth_header.split(' ')[1]
    payload = jwt_service.decode_token(token)
    
    if "error" in payload:
        return jsonify(payload), 401
        
    if payload.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403
        
    return jsonify({"message": f"Welcome Admin {payload.get('sub')}", "data": "Top secret files."})

if __name__ == '__main__':
    print("[*] Secure JWT Auth Server running on port 5000")
    app.run(port=5000)
