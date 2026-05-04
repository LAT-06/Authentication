import uuid
from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Áp dụng SRP: Quản lý người dùng
class UserRepository:
    def __init__(self):
        self._users = {"admin": generate_password_hash("SuperSecret123")}
        
    def verify(self, username, password):
        user_hash = self._users.get(username)
        return check_password_hash(user_hash, password) if user_hash else False

# Áp dụng SRP: Quản lý Session
class SessionManager:
    def __init__(self):
        self._sessions = {} # Trong thực tế production, thay dict này bằng Redis
        
    def create_session(self, username):
        # BẬT TÍNH NĂNG NÀY: Dùng UUID v4 để sinh Session ID ngẫu nhiên, không thể đoán trước.
        # NẾU KHÔNG BẬT: Attacker có thể đoán thuật toán sinh ID để chiếm tài khoản người khác.
        session_id = str(uuid.uuid4())
        self._sessions[session_id] = username
        return session_id
        
    def get_user(self, session_id):
        return self._sessions.get(session_id)

user_repo = UserRepository()
session_manager = SessionManager()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or not user_repo.verify(data.get('username'), data.get('password')):
        return jsonify({"error": "Unauthorized"}), 401
    
    session_id = session_manager.create_session(data['username'])
    resp = make_response(jsonify({"message": "Login successful"}))
    
    # BẬT TÍNH NĂNG NÀY: Set các cờ bảo mật cho Cookie.
    # NẾU KHÔNG BẬT:
    # 1. Thiếu HttpOnly -> Dễ bị mã độc XSS trộm cookie bằng JavaScript.
    # 2. Thiếu Secure -> Cookie bị lộ nếu mạng không có HTTPS.
    # 3. Thiếu SameSite -> Dễ bị tấn công CSRF (kẻ gian lừa user gửi request trái phép).
    resp.set_cookie(
        'session_id', 
        session_id, 
        httponly=True, 
        secure=True, 
        samesite='Strict'
    )
    return resp

@app.route('/profile')
def profile():
    session_id = request.cookies.get('session_id')
    user = session_manager.get_user(session_id)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
        
    return jsonify({"message": f"Welcome {user}", "data": "Top secret dashboard."})

if __name__ == '__main__':
    app.run(port=5000)
