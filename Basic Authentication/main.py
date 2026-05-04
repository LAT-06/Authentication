from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# BẬT TÍNH NĂNG NÀY: Rate Limiting để chống Brute-force.
# NẾU KHÔNG BẬT: Attacker có thể thử hàng triệu password mỗi phút cho đến khi đúng.
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Áp dụng SRP: Lớp chịu trách nhiệm tương tác dữ liệu (Mô phỏng Database)
class UserRepository:
    def __init__(self):
        # BẬT TÍNH NĂNG NÀY: Hash password thay vì lưu plaintext.
        # NẾU KHÔNG BẬT: Database bị leak là mất toàn bộ mật khẩu gốc của user.
        self._users = {
            "admin": generate_password_hash("SuperSecret123")
        }

    def get_user_hash(self, username: str) -> str:
        return self._users.get(username)

# Áp dụng SRP & DIP: Lớp chịu trách nhiệm xác thực, nhận dependency từ bên ngoài
class BasicAuthenticator:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    def authenticate(self, username, password) -> bool:
        user_hash = self.user_repo.get_user_hash(username)
        if not user_hash:
            return False
        return check_password_hash(user_hash, password)

# Khởi tạo dependencies
repo = UserRepository()
authenticator = BasicAuthenticator(repo)

@app.route('/secure-data')
@limiter.limit("5 per minute")
def secure_data():
    auth = request.authorization
    
    if not auth or not authenticator.authenticate(auth.username, auth.password):
        # Đã sửa: Trả về thêm header WWW-Authenticate để trình duyệt biết và gọi popup
        return jsonify({"error": "Unauthorized"}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}
    
    return jsonify({"message": "Successfully", "data": "Your Mom Weight"})

if __name__ == '__main__':
    app.run(port=5000)
