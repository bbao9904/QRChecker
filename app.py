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
import threading

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

# ===== Thêm cache & throttle =====
URL_CACHE = {}  # { url: (timestamp, (is_safe, message, details)) }
CACHE_TTL = 15 * 60  # 15 phút
LAST_VT_CALL = 0
MIN_INTERVAL = 16      # 4 request/phút
VT_LOCK = threading.Lock()

def _cache_get(url):
    item = URL_CACHE.get(url)
    if not item: return None
    ts, data = item
    if time.time() - ts > CACHE_TTL:
        URL_CACHE.pop(url, None)
        return None
    return data

def _cache_set(url, data):
    URL_CACHE[url] = (time.time(), data)

def _throttle():
    global LAST_VT_CALL
    with VT_LOCK:
        delta = time.time() - LAST_VT_CALL
        if delta < MIN_INTERVAL:
            time.sleep(MIN_INTERVAL - delta)
        LAST_VT_CALL = time.time()

def _safe_json(resp):
    if resp.status_code in (204, 429):
        # 204: quota limit (No Content), 429: too many requests
        raise RuntimeError("Rate limit VirusTotal: đợi khoảng 20s rồi thử lại.")
    if resp.status_code in (401, 403):
        raise RuntimeError(f"API key không hợp lệ / bị từ chối (status {resp.status_code}).")
    ctype = resp.headers.get("Content-Type", "")
    if "application/json" not in ctype.lower():
        # Có thể là HTML thông báo quota
        raise RuntimeError(f"Phản hồi không phải JSON (status {resp.status_code}).")
    try:
        return resp.json()
    except ValueError:
        raise RuntimeError("Không parse được JSON.")

def check_url_safety(url):
    """Kiểm tra an toàn URL với cache + throttle + xử lý rate limit."""
    try:
        # 0. Cache
        cached = _cache_get(url)
        if cached:
            return cached

        # 1. Validate
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            result = (False, "URL không hợp lệ", {})
            _cache_set(url, result); return result

        for pattern in [r"\.exe$", r"\.bat$", r"\.cmd$", r"data:text/html", r"javascript:"]:
            if re.search(pattern, url.lower()):
                result = (False, f"URL chứa pattern nguy hiểm: {pattern}", {})
                _cache_set(url, result); return result

        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        # 2. Throttle + GET cached VT
        _throttle()
        resp = requests.get(vt_url, headers=headers, timeout=20)
        if resp.status_code == 404:
            # Chưa có -> submit
            _throttle()
            sub = requests.post("https://www.virustotal.com/api/v3/urls",
                                headers=headers, data={"url": url}, timeout=20)
            # Có thể bị rate limit ở submit
            if sub.status_code in (204, 429):
                return False, "Rate limit khi submit URL (đợi rồi thử lại)", {
                    "malicious":0,"suspicious":0,"clean":0,"total":0
                }
            time.sleep(5)  # chờ VT phân tích
            _throttle()
            resp = requests.get(vt_url, headers=headers, timeout=20)

        # 3. Parse an toàn
        try:
            data = _safe_json(resp)
        except RuntimeError as e:
            return False, str(e), {"malicious":0,"suspicious":0,"clean":0,"total":0}

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        clean = int(stats.get("harmless", 0))
        total = malicious + suspicious + clean

        if total == 0:
            # Không cache 0 để có thể thử lại sau
            return False, "Chưa có kết quả phân tích từ VirusTotal", {
                "malicious":0,"suspicious":0,"clean":0,"total":0
            }

        details = {
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": clean,
            "total": total
        }

        if malicious > 0:
            result = (False, f"Phát hiện độc hại ({malicious} engines)", details)
        elif suspicious > 0:
            result = (False, f"Đáng ngờ ({suspicious} engines)", details)
        else:
            result = (True, f"An toàn ({clean} engines xác nhận)", details)

        _cache_set(url, result)
        return result

    except Exception as e:
        return False, f"Lỗi kiểm tra: {e}", {
            "malicious":0,"suspicious":0,"clean":0,"total":0
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