from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

USERS = {"admin": "password123"}

# LỖ HỔNG 1: Lưu trữ session cẩu thả
SESSIONS = {}

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if USERS.get(username) == password:
        # LỖ HỔNG 2: Thuật toán sinh Session ID có thể đoán được (Predictable Session ID)
        session_id = f"{username}_active_session"
        SESSIONS[session_id] = username
        
        resp = make_response(jsonify({"message": "Login successful"}))
        # LỖ HỔNG 3: Set cookie trần trụi, không có HttpOnly, Secure hay SameSite
        resp.set_cookie('session_id', session_id)
        return resp
        
    return jsonify({"error": "Unauthorized"}), 401

@app.route('/profile')
def profile():
    session_id = request.cookies.get('session_id')
    user = SESSIONS.get(session_id)
    
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
        
    return jsonify({"message": f"Welcome {user}", "data": "Server đã bị chiếm quyền."})
    
if __name__ == '__main__':
    app.run(port=5001)
