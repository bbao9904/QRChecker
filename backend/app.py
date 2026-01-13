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
import qrcode
from io import BytesIO

# Import subscription modules
from subscription import init_subscription_tables, check_scan_permission, check_feature_permission
from subscription_routes import subscription_bp

load_dotenv()

app = Flask(
    __name__,
    template_folder='../frontend',
    static_folder='../frontend',
    static_url_path=''  # cho phép /style.css
)
app.secret_key = os.getenv("APP_SECRET", "dev_change_me")
app.permanent_session_lifetime = timedelta(days=7)

# Register subscription blueprint
app.register_blueprint(subscription_bp)

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
    
    # Thêm bảng lịch sử quét
    c.execute("""
      CREATE TABLE IF NOT EXISTS scan_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        qr_type TEXT NOT NULL,
        qr_content TEXT NOT NULL,
        result TEXT,
        is_safe INTEGER DEFAULT 1,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    """)
    
    # Thêm bảng lịch sử tạo mã
    c.execute("""
      CREATE TABLE IF NOT EXISTS create_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        qr_type TEXT NOT NULL,
        qr_content TEXT NOT NULL,
        qr_image TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    """)
    
    conn.commit()
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (username,email,password,is_admin) VALUES (?,?,?,1)",
                  ("admin","admin@example.com", generate_password_hash("admin123")))
        conn.commit()
    conn.close()
    
    # Khởi tạo subscription tables
    init_subscription_tables()

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

# ===== ADMIN - XEM LỊCH SỬ USER =====
@app.route('/admin/user/<int:user_id>/history/scan', methods=['GET'])
def admin_get_user_scan_history(user_id):
    """Admin xem lịch sử quét của user"""
    if not session.get("is_admin"):
        return jsonify({"status": "fail", "msg": "Không có quyền truy cập"}), 403
    
    conn = get_db(); c = conn.cursor()
    
    # Lấy thông tin user
    c.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
    user_row = c.fetchone()
    if not user_row:
        conn.close()
        return jsonify({"status": "fail", "msg": "Không tìm thấy user"}), 404
    
    # Lấy lịch sử quét
    c.execute("""
        SELECT id, qr_type, qr_content, result, is_safe, details, created_at
        FROM scan_history
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 200
    """, (user_id,))
    
    rows = c.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            "id": row[0],
            "qr_type": row[1],
            "qr_content": row[2],
            "result": row[3],
            "is_safe": bool(row[4]),
            "details": json.loads(row[5]) if row[5] else {},
            "created_at": row[6]
        })
    
    return jsonify({
        "status": "ok",
        "user": {
            "id": user_id,
            "username": user_row[0],
            "email": user_row[1]
        },
        "history": history
    })

@app.route('/admin/user/<int:user_id>/history/create', methods=['GET'])
def admin_get_user_create_history(user_id):
    """Admin xem lịch sử tạo mã của user"""
    if not session.get("is_admin"):
        return jsonify({"status": "fail", "msg": "Không có quyền truy cập"}), 403
    
    conn = get_db(); c = conn.cursor()
    
    # Lấy thông tin user
    c.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
    user_row = c.fetchone()
    if not user_row:
        conn.close()
        return jsonify({"status": "fail", "msg": "Không tìm thấy user"}), 404
    
    # Lấy lịch sử tạo mã
    c.execute("""
        SELECT id, qr_type, qr_content, qr_image, created_at
        FROM create_history
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 200
    """, (user_id,))
    
    rows = c.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            "id": row[0],
            "qr_type": row[1],
            "qr_content": row[2],
            "qr_image": f"data:image/png;base64,{row[3]}" if row[3] else None,
            "created_at": row[4]
        })
    
    return jsonify({
        "status": "ok",
        "user": {
            "id": user_id,
            "username": user_row[0],
            "email": user_row[1]
        },
        "history": history
    })

@app.route('/admin/user/<int:user_id>/history/stats', methods=['GET'])
def admin_get_user_history_stats(user_id):
    """Admin xem thống kê lịch sử của user"""
    if not session.get("is_admin"):
        return jsonify({"status": "fail", "msg": "Không có quyền truy cập"}), 403
    
    conn = get_db(); c = conn.cursor()
    
    # Lấy thông tin user
    c.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
    user_row = c.fetchone()
    if not user_row:
        conn.close()
        return jsonify({"status": "fail", "msg": "Không tìm thấy user"}), 404
    
    # Thống kê quét mã
    c.execute("SELECT COUNT(*) FROM scan_history WHERE user_id = ?", (user_id,))
    total_scans = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND is_safe = 1", (user_id,))
    safe_scans = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND is_safe = 0", (user_id,))
    danger_scans = c.fetchone()[0]
    
    # Thống kê tạo mã
    c.execute("SELECT COUNT(*) FROM create_history WHERE user_id = ?", (user_id,))
    total_creates = c.fetchone()[0]
    
    # Thống kê theo type
    c.execute("""
        SELECT qr_type, COUNT(*) 
        FROM scan_history 
        WHERE user_id = ? 
        GROUP BY qr_type
    """, (user_id,))
    scan_by_type = dict(c.fetchall())
    
    c.execute("""
        SELECT qr_type, COUNT(*) 
        FROM create_history 
        WHERE user_id = ? 
        GROUP BY qr_type
    """, (user_id,))
    create_by_type = dict(c.fetchall())
    
    conn.close()
    
    return jsonify({
        "status": "ok",
        "user": {
            "id": user_id,
            "username": user_row[0],
            "email": user_row[1]
        },
        "stats": {
            "scan": {
                "total": total_scans,
                "safe": safe_scans,
                "danger": danger_scans,
                "by_type": scan_by_type
            },
            "create": {
                "total": total_creates,
                "by_type": create_by_type
            }
        }
    })

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
    
    user_id = session.get("user_id")
    is_admin = session.get("is_admin", False)
    
    # Kiểm tra giới hạn quét
    allowed, error_msg = check_scan_permission(user_id, is_admin)
    if not allowed:
        return jsonify(error_msg), 403
    
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

        qr_type = "text"
        result_msg = ""
        is_safe = True
        details_json = "{}"

        # 1) WiFi QR
        wifi_info = parse_wifi_qr(qr_data)
        if wifi_info:
            qr_type = "wifi"
            result_msg = "Thông tin WiFi"
            details_json = json.dumps(wifi_info)
            
            # Lưu lịch sử
            conn = get_db(); c = conn.cursor()
            c.execute("""
                INSERT INTO scan_history (user_id, qr_type, qr_content, result, is_safe, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, qr_type, qr_data, result_msg, 1, details_json))
            conn.commit(); conn.close()
            
            return jsonify({
                "result": result_msg,
                "data": qr_data,
                "wifi": wifi_info,
                "is_safe": True
            })

        # 1.1) Email (mailto:)
        email_info = parse_mailto(qr_data)
        if email_info:
            qr_type = "email"
            result_msg = "Email"
            details_json = json.dumps(email_info)
            
            conn = get_db(); c = conn.cursor()
            c.execute("""
                INSERT INTO scan_history (user_id, qr_type, qr_content, result, is_safe, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, qr_type, qr_data, result_msg, 1, details_json))
            conn.commit(); conn.close()
            
            return jsonify({
                "result": result_msg,
                "data": qr_data,
                "email": email_info,
                "is_safe": True
            })

        # 1.2) Điện thoại (tel:)
        phone_info = parse_tel(qr_data)
        if phone_info:
            qr_type = "phone"
            result_msg = "Số điện thoại"
            details_json = json.dumps(phone_info)
            
            conn = get_db(); c = conn.cursor()
            c.execute("""
                INSERT INTO scan_history (user_id, qr_type, qr_content, result, is_safe, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, qr_type, qr_data, result_msg, 1, details_json))
            conn.commit(); conn.close()
            
            return jsonify({
                "result": result_msg,
                "data": qr_data,
                "phone": phone_info,
                "is_safe": True
            })

        # 1.3) SMS (sms:/SMSTO:)
        sms_info = parse_sms(qr_data)
        if sms_info:
            qr_type = "sms"
            result_msg = "Tin nhắn SMS"
            details_json = json.dumps(sms_info)
            
            conn = get_db(); c = conn.cursor()
            c.execute("""
                INSERT INTO scan_history (user_id, qr_type, qr_content, result, is_safe, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, qr_type, qr_data, result_msg, 1, details_json))
            conn.commit(); conn.close()
            
            return jsonify({
                "result": result_msg,
                "data": qr_data,
                "sms": sms_info,
                "is_safe": True
            })

        # 1.5) Plain text (không phải URL http/https)
        if not looks_like_url(qr_data):
            qr_type = "text"
            result_msg = "Nội dung văn bản"
            details_json = json.dumps({"content": qr_data, "length": len(qr_data)})
            
            conn = get_db(); c = conn.cursor()
            c.execute("""
                INSERT INTO scan_history (user_id, qr_type, qr_content, result, is_safe, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, qr_type, qr_data, result_msg, 1, details_json))
            conn.commit(); conn.close()
            
            return jsonify({
                "result": result_msg,
                "data": qr_data,
                "text": { "content": qr_data, "length": len(qr_data) },
                "is_safe": True
            })

        # 2) Danh sách an toàn cục bộ
        if qr_data in SAFE_QR_LIST:
            qr_type = "url"
            result_msg = "Mã QR an toàn"
            
            conn = get_db(); c = conn.cursor()
            c.execute("""
                INSERT INTO scan_history (user_id, qr_type, qr_content, result, is_safe, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, qr_type, qr_data, result_msg, 1, "{}"))
            conn.commit(); conn.close()
            
            return jsonify({"result": result_msg, "data": qr_data, "is_safe": True})

        # 3) Kiểm tra URL (VirusTotal)
        qr_type = "url"
        is_safe, message, vt_details = check_url_safety(qr_data)
        result_msg = message
        details_json = json.dumps(vt_details)
        
        conn = get_db(); c = conn.cursor()
        c.execute("""
            INSERT INTO scan_history (user_id, qr_type, qr_content, result, is_safe, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, qr_type, qr_data, result_msg, 1 if is_safe else 0, details_json))
        conn.commit(); conn.close()
        
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

# ===== TẠO MÃ QR =====
@app.route('/create_qr', methods=['POST'])
def create_qr():
    """
    Tạo mã QR từ nhiều loại dữ liệu với validation chặt chẽ
    """
    if "user_id" not in session:
        return jsonify({"status": "fail", "msg": "Bạn cần đăng nhập để sử dụng chức năng này"}), 401
    
    user_id = session.get("user_id")
    is_admin = session.get("is_admin", False)
    
    # Kiểm tra quyền truy cập
    allowed, error_msg = check_feature_permission(user_id, is_admin, 'create')
    if not allowed:
        return jsonify(error_msg), 403
    
    try:
        data = request.get_json()
        qr_type = data.get('type', 'url').lower()
        qr_content = ""
        
        if qr_type == 'url':
            url = data.get('url', '').strip()
            
            # 1. Kiểm tra rỗng
            if not url:
                return jsonify({
                    "status": "fail", 
                    "msg": "❌ URL không được để trống. Vui lòng nhập địa chỉ website.",
                    "field": "url"
                }), 400
            
            # 2. Kiểm tra có phải URL không
            if not url.startswith(('http://', 'https://', 'ftp://', 'www.')):
                # Kiểm tra xem có chứa dấu cách hoặc ký tự đặc biệt của văn bản
                if ' ' in url or '\n' in url or len(url.split()) > 1:
                    return jsonify({
                        "status": "fail",
                        "msg": f"❌ Đây không phải là URL hợp lệ!\n\nBạn đã nhập văn bản: '{url[:50]}...'\n\nVui lòng chọn tab '📝 Text' nếu muốn tạo mã QR cho văn bản.",
                        "field": "url",
                        "suggestion": "text"
                    }), 400
                
                # Không có http/https -> thêm https://
                url = 'https://' + url
            
            # 3. Parse và validate URL
            try:
                parsed = urlparse(url)
                
                # Kiểm tra có netloc (domain)
                if not parsed.netloc:
                    return jsonify({
                        "status": "fail",
                        "msg": f"❌ URL không hợp lệ: '{url}'\n\nURL phải có định dạng: https://example.com",
                        "field": "url"
                    }), 400
                
                # Kiểm tra domain hợp lệ
                domain = parsed.netloc.lower()
                if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$', domain.split(':')[0]):
                    return jsonify({
                        "status": "fail",
                        "msg": f"❌ Tên miền không hợp lệ: '{domain}'\n\nVí dụ đúng: example.com, google.com",
                        "field": "url"
                    }), 400
                
            except Exception as e:
                return jsonify({
                    "status": "fail",
                    "msg": f"❌ URL không hợp lệ: {str(e)}",
                    "field": "url"
                }), 400
            
            # 4. Kiểm tra các pattern nguy hiểm
            dangerous_patterns = {
                r'\.exe(\?|$|#)': 'file thực thi (.exe)',
                r'\.bat(\?|$|#)': 'file batch (.bat)',
                r'\.cmd(\?|$|#)': 'file command (.cmd)',
                r'\.scr(\?|$|#)': 'file screensaver (.scr)',
                r'\.vbs(\?|$|#)': 'file VBScript (.vbs)',
                r'\.jar(\?|$|#)': 'file Java (.jar)',
                r'data:text/html': 'Data URI chứa HTML',
                r'javascript:': 'JavaScript URI',
                r'vbscript:': 'VBScript URI',
            }
            
            for pattern, desc in dangerous_patterns.items():
                if re.search(pattern, url.lower()):
                    return jsonify({
                        "status": "fail",
                        "msg": f"🚫 URL bị chặn!\n\nPhát hiện {desc} - đây là loại URL nguy hiểm.\n\nChúng tôi không thể tạo mã QR cho URL này vì lý do bảo mật.",
                        "field": "url",
                        "danger_type": desc
                    }), 400
            
            # 5. Kiểm tra an toàn URL với VirusTotal (nếu được bật)
            check_safety = data.get('check_safety', True)
            if check_safety:
                is_safe, message, vt_details = check_url_safety(url)
                
                if not is_safe:
                    malicious = vt_details.get('malicious', 0)
                    suspicious = vt_details.get('suspicious', 0)
                    total = vt_details.get('total', 0)
                    
                    danger_msg = "⛔ URL NGUY HIỂM - Không thể tạo mã QR!\n\n"
                    
                    if malicious > 0:
                        danger_msg += f"🔴 {malicious}/{total} công cụ bảo mật xác nhận đây là URL ĐỘC HẠI.\n\n"
                    elif suspicious > 0:
                        danger_msg += f"🟡 {suspicious}/{total} công cụ bảo mật đánh dấu URL này là ĐÁNG NGỜ.\n\n"
                    else:
                        danger_msg += f"⚠️ {message}\n\n"
                    
                    danger_msg += "Lý do: URL này có thể chứa:\n"
                    danger_msg += "• Phần mềm độc hại (malware)\n"
                    danger_msg += "• Trang web lừa đảo (phishing)\n"
                    danger_msg += "• Nội dung bạn đưa vào không phải là URL hợp lệ\n"
                    danger_msg += "• Nội dung nguy hiểm khác\n\n"
                    danger_msg += "👉 Vui lòng kiểm tra lại URL hoặc sử dụng URL khác."
                    
                    return jsonify({
                        "status": "fail",
                        "msg": danger_msg,
                        "details": vt_details,
                        "field": "url",
                        "danger_level": "high" if malicious > 0 else "medium"
                    }), 400
            
            qr_content = url
            
        elif qr_type == 'text':
            content = data.get('content', '').strip()
            
            if not content:
                return jsonify({
                    "status": "fail", 
                    "msg": "❌ Nội dung văn bản không được để trống.",
                    "field": "content"
                }), 400
            
            # Kiểm tra độ dài
            if len(content) > 1000:
                return jsonify({
                    "status": "fail",
                    "msg": f"❌ Nội dung quá dài ({len(content)} ký tự)!\n\nĐể mã QR dễ quét, vui lòng giới hạn dưới 1000 ký tự.\n\nHiện tại: {len(content)} ký tự\nTối đa: 1000 ký tự",
                    "field": "content"
                }), 400
            
            # Cảnh báo nếu content trông như URL
            if looks_like_url(content):
                return jsonify({
                    "status": "fail",
                    "msg": f"⚠️ Phát hiện URL trong nội dung văn bản!\n\nBạn đã nhập: '{content[:100]}...'\n\nVui lòng chọn tab '🔗 URL' để tạo mã QR cho địa chỉ website.",
                    "field": "content",
                    "suggestion": "url"
                }), 400
            
            qr_content = content
            
        elif qr_type == 'wifi':
            ssid = data.get('ssid', '').strip()
            password = data.get('password', '').strip()
            encryption = data.get('encryption', 'WPA').upper()
            hidden = data.get('hidden', False)
            
            if not ssid:
                return jsonify({
                    "status": "fail", 
                    "msg": "❌ Tên WiFi (SSID) không được để trống.",
                    "field": "ssid"
                }), 400
            
            # Validate SSID (tối đa 32 ký tự)
            if len(ssid) > 32:
                return jsonify({
                    "status": "fail",
                    "msg": f"❌ Tên WiFi quá dài ({len(ssid)} ký tự)!\n\nSSID chỉ được phép tối đa 32 ký tự.",
                    "field": "ssid"
                }), 400
            
            # Validate password theo encryption
            if encryption in ('WPA', 'WPA2', 'WPA3'):
                if password and (len(password) < 8 or len(password) > 63):
                    return jsonify({
                        "status": "fail",
                        "msg": f"❌ Mật khẩu WPA không hợp lệ!\n\nMật khẩu WPA/WPA2 phải có từ 8-63 ký tự.\nHiện tại: {len(password)} ký tự",
                        "field": "password"
                    }), 400
            
            # Escape các ký tự đặc biệt
            def escape_wifi(s):
                return s.replace('\\', '\\\\').replace(';', '\\;').replace(':', '\\:').replace(',', '\\,').replace('"', '\\"')
            
            ssid_escaped = escape_wifi(ssid)
            pass_escaped = escape_wifi(password)
            
            qr_content = f'WIFI:T:{encryption};S:{ssid_escaped};P:{pass_escaped};H:{"true" if hidden else "false"};;'
            
        elif qr_type == 'phone':
            number = data.get('number', '').strip()
            
            if not number:
                return jsonify({
                    "status": "fail", 
                    "msg": "❌ Số điện thoại không được để trống.",
                    "field": "number"
                }), 400
            
            # Validate phone number (chỉ cho phép số, +, -, khoảng trắng, dấu ngoặc)
            cleaned = re.sub(r'[\s\-\(\)]', '', number)
            if not re.match(r'^\+?\d{8,15}$', cleaned):
                return jsonify({
                    "status": "fail",
                    "msg": f"❌ Số điện thoại không hợp lệ!\n\nSố điện thoại phải:\n• Chỉ chứa chữ số (0-9)\n• Có thể bắt đầu bằng +\n• Độ dài 8-15 chữ số\n\nVí dụ: +84123456789 hoặc 0123456789",
                    "field": "number"
                }), 400
            
            qr_content = f'tel:{number}'
            
        elif qr_type == 'sms':
            number = data.get('number', '').strip()
            body = data.get('body', '').strip()
            
            if not number:
                return jsonify({
                    "status": "fail", 
                    "msg": "❌ Số điện thoại không được để trống.",
                    "field": "number"
                }), 400
            
            # Validate phone
            cleaned = re.sub(r'[\s\-\(\)]', '', number)
            if not re.match(r'^\+?\d{8,15}$', cleaned):
                return jsonify({
                    "status": "fail",
                    "msg": f"❌ Số điện thoại không hợp lệ! (Xem hướng dẫn ở tab Phone)",
                    "field": "number"
                }), 400
            
            # Validate body length
            if len(body) > 160:
                return jsonify({
                    "status": "fail",
                    "msg": f"⚠️ Nội dung tin nhắn quá dài ({len(body)} ký tự)!\n\nĐề xuất giới hạn 160 ký tự để tương thích tốt nhất.",
                    "field": "body"
                }), 400
            
            qr_content = f'sms:{number}?body={body}' if body else f'sms:{number}'
            
        elif qr_type == 'email':
            to = data.get('to', '').strip()
            subject = data.get('subject', '').strip()
            body = data.get('body', '').strip()
            
            if not to:
                return jsonify({
                    "status": "fail", 
                    "msg": "❌ Email người nhận không được để trống.",
                    "field": "to"
                }), 400
            
            # Validate email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, to):
                return jsonify({
                    "status": "fail",
                    "msg": f"❌ Email không hợp lệ: '{to}'\n\nVí dụ đúng: user@example.com",
                    "field": "to"
                }), 400
            
            params = []
            if subject:
                params.append(f'subject={subject}')
            if body:
                params.append(f'body={body}')
            
            qr_content = f'mailto:{to}' + ('?' + '&'.join(params) if params else '')
        else:
            return jsonify({"status": "fail", "msg": f"❌ Loại QR '{qr_type}' không được hỗ trợ."}), 400
        
        # Tạo mã QR
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(qr_content)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        qr_image_data = f"data:image/png;base64,{img_base64}"
        
        # Lưu lịch sử tạo mã
        conn = get_db(); c = conn.cursor()
        c.execute("""
            INSERT INTO create_history (user_id, qr_type, qr_content, qr_image)
            VALUES (?, ?, ?, ?)
        """, (user_id, qr_type, qr_content, img_base64))
        conn.commit(); conn.close()
        
        return jsonify({
            "status": "ok",
            "qr_image": qr_image_data,
            "qr_content": qr_content,
            "type": qr_type,
            "msg": " Tạo mã QR thành công!"
        })
        
    except Exception as e:
        return jsonify({"status": "fail", "msg": f"❌ Lỗi không xác định khi tạo mã QR:\n{str(e)}"}), 500

# ===== API LỊCH SỬ =====
@app.route('/history/scan', methods=['GET'])
def get_scan_history():
    """Lấy lịch sử quét mã QR"""
    if "user_id" not in session:
        return jsonify({"status": "fail", "msg": "Chưa đăng nhập"}), 401
    
    user_id = session.get("user_id")
    is_admin = session.get("is_admin", False)
    
    allowed, error_msg = check_feature_permission(user_id, is_admin, 'history')
    if not allowed:
        return jsonify(error_msg), 403
    
    conn = get_db(); c = conn.cursor()
    c.execute("""
        SELECT id, qr_type, qr_content, result, is_safe, details, created_at
        FROM scan_history
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 100
    """, (user_id,))
    
    rows = c.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            "id": row[0],
            "qr_type": row[1],
            "qr_content": row[2],
            "result": row[3],
            "is_safe": bool(row[4]),
            "details": json.loads(row[5]) if row[5] else {},
            "created_at": row[6]
        })
    
    return jsonify({"status": "ok", "history": history})

@app.route('/history/create', methods=['GET'])
def get_create_history():
    """Lấy lịch sử tạo mã QR"""
    if "user_id" not in session:
        return jsonify({"status": "fail", "msg": "Chưa đăng nhập"}), 401
    
    user_id = session.get("user_id")
    is_admin = session.get("is_admin", False)
    
    allowed, error_msg = check_feature_permission(user_id, is_admin, 'history')
    if not allowed:
        return jsonify(error_msg), 403
    
    conn = get_db(); c = conn.cursor()
    c.execute("""
        SELECT id, qr_type, qr_content, qr_image, created_at
        FROM create_history
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 100
    """, (user_id,))
    
    rows = c.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            "id": row[0],
            "qr_type": row[1],
            "qr_content": row[2],
            "qr_image": f"data:image/png;base64,{row[3]}" if row[3] else None,
            "created_at": row[4]
        })
    
    return jsonify({"status": "ok", "history": history})

@app.route('/history/scan/<int:history_id>', methods=['DELETE'])
def delete_scan_history(history_id):
    """Xóa một lịch sử quét"""
    if "user_id" not in session:
        return jsonify({"status": "fail", "msg": "Chưa đăng nhập"}), 401
    
    user_id = session.get("user_id")
    conn = get_db(); c = conn.cursor()
    c.execute("DELETE FROM scan_history WHERE id = ? AND user_id = ?", (history_id, user_id))
    conn.commit(); conn.close()
    
    return jsonify({"status": "ok", "msg": "Đã xóa lịch sử"})

@app.route('/history/create/<int:history_id>', methods=['DELETE'])
def delete_create_history(history_id):
    """Xóa một lịch sử tạo mã"""
    if "user_id" not in session:
        return jsonify({"status": "fail", "msg": "Chưa đăng nhập"}), 401
    
    user_id = session.get("user_id")
    conn = get_db(); c = conn.cursor()
    c.execute("DELETE FROM create_history WHERE id = ? AND user_id = ?", (history_id, user_id))
    conn.commit(); conn.close()
    
    return jsonify({"status": "ok", "msg": "Đã xóa lịch sử"})

@app.route('/history/scan/clear', methods=['DELETE'])
def clear_scan_history():
    """Xóa tất cả lịch sử quét"""
    if "user_id" not in session:
        return jsonify({"status": "fail", "msg": "Chưa đăng nhập"}), 401
    
    user_id = session.get("user_id")
    conn = get_db(); c = conn.cursor()
    c.execute("DELETE FROM scan_history WHERE user_id = ?", (user_id,))
    conn.commit(); conn.close()
    
    return jsonify({"status": "ok", "msg": "Đã xóa toàn bộ lịch sử quét"})

@app.route('/history/create/clear', methods=['DELETE'])
def clear_create_history():
    """Xóa tất cả lịch sử tạo mã"""
    if "user_id" not in session:
        return jsonify({"status": "fail", "msg": "Chưa đăng nhập"}), 401
    
    user_id = session.get("user_id")
    conn = get_db(); c = conn.cursor()
    c.execute("DELETE FROM create_history WHERE user_id = ?", (user_id,))
    conn.commit(); conn.close()
    
    return jsonify({"status": "ok", "msg": "Đã xóa toàn bộ lịch sử tạo mã"})

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