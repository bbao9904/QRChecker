from flask import Flask, request, jsonify, render_template
from pyzbar.pyzbar import decode
from PIL import Image
from pyngrok import ngrok
import json
import os
import requests
import re
import base64
import time
from urllib.parse import urlparse

app = Flask(
    __name__,
    template_folder='../frontend',
    static_folder='../frontend',
    static_url_path=''  # cho phép /style.css
)

# Load danh sách mã QR an toàn
with open('safe_qr_list.json', 'r', encoding='utf-8') as f:
    SAFE_QR_LIST = json.load(f)

# Thêm API key của VirusTotal 
VIRUSTOTAL_API_KEY = "4f89f9c7346c91969c99187def022dd96052b0c18b205ec2942813513e219ce5"

def check_url_safety(url):
    """Kiểm tra URL có an toàn không"""
    try:
        # 1. Kiểm tra định dạng URL
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return False, "URL không hợp lệ", {}

        # 2. Kiểm tra các pattern nguy hiểm
        dangerous_patterns = [
            r"\.exe$", r"\.bat$", r"\.cmd$",
            r"data:text/html",
            r"javascript:",
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, url.lower()):
                return False, f"URL chứa pattern nguy hiểm: {pattern}", {}

        # 3. Kiểm tra với VirusTotal API
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        
        # Đầu tiên submit URL để phân tích
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        submit_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        print("Đang gửi request tới:", submit_url) # Debug log
        
        print(f"\nĐang kiểm tra URL: {url}")
        response = requests.get(submit_url, headers=headers)
        results = response.json()
        
        # Chỉ in thông tin quan trọng
        if "data" in results:
            stats = results["data"]["attributes"]["last_analysis_stats"]
            print("\nKết quả VirusTotal:")
            print(f"✓ An toàn: {stats.get('harmless', 0)}")
            print(f"⚠ Đáng ngờ: {stats.get('suspicious', 0)}")
            print(f"✕ Độc hại: {stats.get('malicious', 0)}\n")
        else:
            print("\nĐang gửi URL để phân tích...")
            analysis_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}
            )
            print("Đang chờ kết quả phân tích...")
            
            # Đợi kết quả phân tích
            time.sleep(5)  # Tăng thời gian chờ
            response = requests.get(submit_url, headers=headers)
            results = response.json()

        # Lấy kết quả phân tích chi tiết
        stats = results.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        
        # Đảm bảo có giá trị mặc định là 0
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        clean = int(stats.get("harmless", 0))
        total = malicious + suspicious + clean
        
        if total == 0:
            return False, "Chưa có kết quả phân tích từ VirusTotal", {
                "malicious": 0,
                "suspicious": 0,
                "clean": 0,
                "total": 0
            }
        
        details = {
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": clean,
            "total": total
        }
        
        if malicious > 0:
            return False, f"Phát hiện độc hại ({malicious} engines)", details
        elif suspicious > 0:
            return False, f"Đáng ngờ ({suspicious} engines)", details
            
        return True, f"An toàn ({clean} engines xác nhận)", details

    except Exception as e:
        print(f"Lỗi khi kiểm tra URL: {str(e)}")  # Log lỗi
        return False, f"Lỗi kiểm tra: {str(e)}", {
            "malicious": 0,
            "suspicious": 0,
            "clean": 0,
            "total": 0
        }

@app.route('/scan', methods=['POST'])
def scan_qr():
    try:
        if 'file' in request.files:
            file = request.files['file']
            img = Image.open(file.stream)
            qr_codes = decode(img)
            if not qr_codes:
                return jsonify({"result": "Không tìm thấy mã QR!"})
            qr_data = qr_codes[0].data.decode('utf-8')
        else:
            data = request.get_json()
            qr_data = data.get('qr_data')
            if not qr_data:
                return jsonify({"result": "Không tìm thấy mã QR!"})
        if qr_data in SAFE_QR_LIST:
            return jsonify({"result": "Mã QR an toàn", "data": qr_data})
        else:
            # Kiểm tra thêm về độ an toàn của URL
            is_safe, message, vt_details = check_url_safety(qr_data)
            if not is_safe:
                return jsonify({
                    "result": f"Cảnh báo: {message}",
                    "data": qr_data,
                    "details": vt_details,
                    "is_safe": False
                })
            return jsonify({
                "result": message,
                "data": qr_data,
                "details": vt_details,
                "is_safe": True
            })
    except Exception as e:
        return jsonify({
            "result": f"Lỗi khi quét mã QR: {str(e)}",
            "data": qr_data if 'qr_data' in locals() else None,
            "details": {},
            "is_safe": False
        })

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, ssl_context='adhoc')

    # ...existing code...

#if __name__ == "__main__":
    # Cấu hình ngrok authtoken
 
 #   ngrok.set_auth_token("YOUR_AUTHTOKEN_HERE")
    
    # Tạo HTTPS tunnel
  #  public_url = ngrok.connect(5000)
   # print(' * Truy cập web qua URL:', public_url)
    
    #app.run(host="0.0.0.0", port=5000)