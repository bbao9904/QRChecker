from flask import Flask, request, jsonify, render_template, session, abort
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from dotenv import load_dotenv
# Thêm các import còn thiếu
import os, json, time, threading, base64, re
#from pyngrok import ngrok
import requests
from urllib.parse import urlparse, parse_qs, unquote
from PIL import Image
from pyzbar.pyzbar import decode

load_dotenv()

app = Flask(
    __name__,
    template_folder='../frontend',
    static_folder='../frontend',
    static_url_path=''  # cho phép /style.css
)
app.secret_key = os.getenv("APP_SECRET", "dev_change_me")
app.permanent_session_lifetime = timedelta(days=7)

VIRUSTOTAL_API_KEY = "4f89f9c7346c91969c99187def022dd96052b0c18b205ec2942813513e219ce5"

# Load danh sách mã QR an toàn (dùng đường dẫn tuyệt đối)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, 'safe_qr_list.json'), 'r', encoding='utf-8') as f:
    SAFE_QR_LIST = json.load(f)
    
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

# ==== SQLite users ====
def get_db():
    return sqlite3.connect('users.db')

def init_db():
    conn = get_db(); c = conn.cursor()
    c.execute("""
      CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        is_admin INTEGER DEFAULT 0
      )
    """)
    conn.commit()
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (username,email,password,is_admin) VALUES (?,?,?,1)",
                  ("admin","admin@example.com", generate_password_hash("admin123")))
        conn.commit()
    conn.close()
 #khổ quá
init_db()

# ==== Auth APIs ====
@app.route("/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    if not username or not email or not password:
        return jsonify({"status":"fail","msg":"Thiếu thông tin"}), 400
    # Kiểm tra độ mạnh mật khẩu (đảm bảo đã khai báo is_strong_password ở trên)
    if not is_strong_password(password):
        return jsonify({"status":"fail","msg":"Mật khẩu phải ≥8 ký tự, gồm chữ thường, CHỮ HOA, số và ký tự đặc biệt."}), 400

    conn = get_db(); c = conn.cursor()
    try:
        # Tiền kiểm trùng lặp để trả lời rõ ràng
        user_exists = c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone() is not None
        email_exists = c.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone() is not None
        if user_exists and email_exists:
            return jsonify({"status":"fail","field":"username","msg":"Tên đăng nhập và email này đã tồn tại. Vui lòng nhập thông tin khác."}), 409
        if user_exists:
            return jsonify({"status":"fail","field":"username","msg":"Tên đăng nhập này đã tồn tại. Vui lòng nhập tên khác."}), 409
        if email_exists:
            return jsonify({"status":"fail","field":"email","msg":"Email này đã được đăng ký. Vui lòng dùng email khác."}), 409

        # Tạo tài khoản
        c.execute("INSERT INTO users (username,email,password) VALUES (?,?,?)",
                  (username, email, generate_password_hash(password)))
        conn.commit()
        return jsonify({"status":"ok"})
    except sqlite3.IntegrityError as e:
        msg = str(e)
        if "users.username" in msg:
            return jsonify({"status":"fail","field":"username","msg":"Tên đăng nhập này đã tồn tại. Vui lòng nhập tên khác."}), 409
        if "users.email" in msg:
            return jsonify({"status":"fail","field":"email","msg":"Email này đã được đăng ký. Vui lòng dùng email khác."}), 409
        return jsonify({"status":"fail","msg":"Không thể tạo tài khoản. Vui lòng thử lại."}), 400
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id,password,is_admin FROM users WHERE username=?", (username,))
    row = c.fetchone(); conn.close()
    if row and check_password_hash(row[1], password):
        session.permanent = True
        session["user_id"] = row[0]
        session["username"] = username
        session["is_admin"] = bool(row[2])
        return jsonify({"status":"ok","is_admin":bool(row[2])})
    return jsonify({"status":"fail","msg":"Sai tài khoản hoặc mật khẩu"}), 401

@app.route("/logout")
def api_logout():
    session.clear()
    return jsonify({"status":"ok"})

@app.route("/me")
def api_me():
    if "user_id" not in session:
        return jsonify({"status":"fail"}), 401
    return jsonify({"username": session["username"], "is_admin": bool(session["is_admin"]) })

# ==== Admin ====
@app.route("/admin/users")
def api_admin_users():
    if not session.get("is_admin"): return abort(403)
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id,username,email,is_admin FROM users")
    users = [{"id":r[0], "username":r[1], "email":r[2], "is_admin":bool(r[3])} for r in c.fetchall()]
    conn.close()
    return jsonify(users)

@app.route("/admin/delete_user", methods=["POST"])
def api_admin_delete_user():
    if not session.get("is_admin"): return abort(403)
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    if not uid: return jsonify({"status":"fail","msg":"Thiếu user_id"}), 400
    if int(uid) == int(session.get("user_id", -1)):
        return jsonify({"status":"fail","msg":"Không thể tự xoá"}), 400
    conn = get_db(); c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit(); conn.close()
    return jsonify({"status":"ok"})

# ==== BẢO VỆ QUÉT ====
def _unescape_wifi(v: str) -> str:
    # Bỏ ngoặc kép ngoài cùng và unescape các ký tự
    v = v.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    v = v.replace(r'\;', ';').replace(r'\:', ':').replace(r'\\', '\\').replace(r'\"', '"').replace(r'\,', ',')
    return v

def parse_wifi_qr(raw: str):
    """
    Chuẩn WIFI: WIFI:T:<auth>;S:<ssid>;P:<password>;H:<hidden>;;
    Ví dụ: WIFI:T:WPA;P:"123456780";S:Wifi Anh Hoanh;
    """
    if not isinstance(raw, str) or not raw.upper().startswith('WIFI:'):
        return None
    s = raw[5:]  # bỏ "WIFI:"
    # Tách theo ; không xét ; đã escape
    parts, cur, esc = [], [], False
    for ch in s:
        if esc:
            cur.append(ch); esc = False
        elif ch == '\\':
            esc = True
        elif ch == ';':
            parts.append(''.join(cur)); cur = []
        else:
            cur.append(ch)
    if cur: parts.append(''.join(cur))

    data = {}
    for p in parts:
        if not p: continue
        # tách theo : đầu tiên (không xét : đã escape – đã xử lý ở vòng lặp)
        k, sep, v = p.partition(':')
        if not sep: continue
        k = k.strip().upper()
        v = _unescape_wifi(v.strip())
        data[k] = v

    auth = (data.get('T') or 'nopass').upper()
    ssid = data.get('S') or ''
    password = data.get('P') or ''
    hidden_raw = (data.get('H') or 'false').strip().lower()
    hidden = hidden_raw in ('1', 'true', 'yes', 'y')

    return {
        "encryption": auth,   # WPA | WEP | nopass
        "ssid": ssid,
        "password": password,
        "hidden": hidden
    }

def looks_like_url(s: str) -> bool:
    if not isinstance(s, str): return False
    p = urlparse(s.strip())
    return bool(p.scheme and p.netloc)

def parse_mailto(raw: str):
    if not isinstance(raw, str) or not raw.lower().startswith('mailto:'):
        return None
    s = raw[7:]
    addr_part, _, qs = s.partition('?')
    to_addr = unquote(addr_part).strip()
    q = parse_qs(qs)
    subject = unquote(q.get('subject', [''])[0])
    body = unquote(q.get('body', [''])[0])
    cc = unquote(','.join(q.get('cc', []))) if 'cc' in q else ''
    bcc = unquote(','.join(q.get('bcc', []))) if 'bcc' in q else ''
    return {"to": to_addr, "subject": subject, "body": body, "cc": cc, "bcc": bcc}

def parse_tel(raw: str):
    if not isinstance(raw, str) or not raw.lower().startswith('tel:'):
        return None
    return {"number": unquote(raw[4:]).strip()}

def parse_sms(raw: str):
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    ls = s.lower()
    if ls.startswith('sms:'):
        r = s[4:]
        num, sep, qs = r.partition('?')
        q = parse_qs(qs)
        body = unquote(q.get('body', [''])[0]) if sep else ''
        return {"number": unquote(num).strip(), "body": body}
    if ls.startswith('smsto:'):
        r = s[6:]
        num, sep, body = r.partition(':')
        return {"number": unquote(num).strip(), "body": unquote(body)}
    return None

@app.route('/scan', methods=['POST'])
def scan_qr():
    if "user_id" not in session:
        return jsonify({"result":"Bạn cần đăng nhập để sử dụng chức năng này."}), 401
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

        # 1) WiFi QR
        wifi_info = parse_wifi_qr(qr_data)
        if wifi_info:
            return jsonify({
                "result": "Thông tin WiFi",
                "data": qr_data,
                "wifi": wifi_info,
                "is_safe": True
            })

        # 1.1) Email (mailto:)
        email_info = parse_mailto(qr_data)
        if email_info:
            return jsonify({
                "result": "Email",
                "data": qr_data,
                "email": email_info,
                "is_safe": True
            })

        # 1.2) Điện thoại (tel:)
        phone_info = parse_tel(qr_data)
        if phone_info:
            return jsonify({
                "result": "Số điện thoại",
                "data": qr_data,
                "phone": phone_info,
                "is_safe": True
            })

        # 1.3) SMS (sms:/SMSTO:)
        sms_info = parse_sms(qr_data)
        if sms_info:
            return jsonify({
                "result": "Tin nhắn SMS",
                "data": qr_data,
                "sms": sms_info,
                "is_safe": True
            })

        # 1.5) Plain text (không phải URL http/https)
        if not looks_like_url(qr_data):
            return jsonify({
                "result": "Nội dung văn bản",
                "data": qr_data,
                "text": { "content": qr_data, "length": len(qr_data) },
                "is_safe": True
            })

        # 2) Danh sách an toàn cục bộ
        if qr_data in SAFE_QR_LIST:
            return jsonify({"result": "Mã QR an toàn", "data": qr_data, "is_safe": True})

        # 3) Kiểm tra URL (VirusTotal)
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

# ==== Password strength (đặt trước route /register) ====
_pw_re_lower = re.compile(r'[a-z]')
_pw_re_upper = re.compile(r'[A-Z]')
_pw_re_digit = re.compile(r'\d')
_pw_re_special = re.compile(r'[^A-Za-z0-9]')

def is_strong_password(pw: str) -> bool:
    return (
        isinstance(pw, str)
        and len(pw) >= 8
        and _pw_re_lower.search(pw)
        and _pw_re_upper.search(pw)
        and _pw_re_digit.search(pw)
        and _pw_re_special.search(pw)
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, ssl_context='adhoc')

    # ...existing code...

#if __name__ == "__main__":
    # Cấu hình ngrok authtoken
 
 #   ngrok.set_auth_token("333PmHKp8go913NiokiYTi6FEWm_Utb5pk5GVq59EFAVee9C")
    
    # Tạo HTTPS tunnel
  #  public_url = ngrok.connect(5000)
   # print(' * Truy cập web qua URL:', public_url)
    
    #app.run(host="0.0.0.0", port=5000)