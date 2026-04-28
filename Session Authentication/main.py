import uuid
import hmac
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# Mock Database cho user
USERS_DB = {"admin": "password123"}

# Mock In-Memory Database cho Session (Thực tế sẽ dùng Redis)
REDIS_MOCK = {}

class SessionManager:
    """Trách nhiệm: Quản lý vòng đời của phiên làm việc phía Server"""
    @staticmethod
    def create_session(username):
        session_id = str(uuid.uuid4())
        REDIS_MOCK[session_id] = username
        return session_id

    @staticmethod
    def get_user_from_session(session_id):
        return REDIS_MOCK.get(session_id)

    @staticmethod
    def destroy_session(session_id):
        if session_id in REDIS_MOCK:
            del REDIS_MOCK[session_id]

def safe_compare(val1, val2):
    if val1 is None or val2 is None:
        return False
    return hmac.compare_digest(val1.encode('utf-8'), val2.encode('utf-8'))

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    expected_password = USERS_DB.get(username)
    
    if safe_compare(password, expected_password):
        # Xác thực thành công, tạo state trên server
        session_id = SessionManager.create_session(username)
        
        # Tạo response và nhét Session ID vào Cookie
        response = make_response(jsonify({"message": "Login Successfully"}))
        response.set_cookie(
            'session_id', 
            session_id, 
            httponly=True,  # Chống XSS
            secure=False,   # Đặt thành True nếu chạy HTTPS
            samesite='Lax'  # Chống CSRF
        )
        return response, 200

    return jsonify({"error": "Wrong information"}), 401

@app.route('/dashboard', methods=['GET'])
def dashboard():
    # Lấy chìa khóa từ trình duyệt gửi lên
    session_id = request.cookies.get('session_id')
    
    if not session_id:
        return jsonify({"error": "Haven't login yet"}), 401
        
    # Tra cứu chìa khóa trên server
    username = SessionManager.get_user_from_session(session_id)
    
    if username:
        return jsonify({"data": f"Hello {username}, this is the data."}), 200
    else:
        return jsonify({"error": "Invalid session or outdated session"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session_id = request.cookies.get('session_id')
    
    # Xóa state trên server
    SessionManager.destroy_session(session_id)
    
    # Ra lệnh cho trình duyệt xóa cookie
    response = make_response(jsonify({"message": "Logout"}))
    response.set_cookie('session_id', '', expires=0)
    return response, 200

if __name__ == '__main__':
    app.run(port=5000)
