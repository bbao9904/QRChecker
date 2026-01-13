import sqlite3
from datetime import datetime, timedelta
import time

DATABASE_PATH = 'users.db'

def get_db():
    """Tạo connection với timeout và WAL mode để tránh lock"""
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn

def init_subscription_tables():
    """Khởi tạo bảng subscription và free scan counter"""
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Bảng subscription (gói dịch vụ)
        c.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                plan_type TEXT NOT NULL,
                start_date TIMESTAMP NOT NULL,
                end_date TIMESTAMP NOT NULL,
                is_active INTEGER DEFAULT 1,
                activated_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        # Thêm cột activated_by nếu chưa có (cho database cũ)
        try:
            c.execute("ALTER TABLE subscriptions ADD COLUMN activated_by TEXT")
        except sqlite3.OperationalError:
            pass  # Cột đã tồn tại
        
        # Bảng đếm scan miễn phí
        c.execute("""
            CREATE TABLE IF NOT EXISTS free_scan_counter(
                user_id INTEGER PRIMARY KEY,
                scan_count INTEGER DEFAULT 0,
                last_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        conn.commit()
    finally:
        conn.close()

# Cấu hình các gói
PLAN_CONFIG = {
    '1_month': {'days': 30, 'price': 30000, 'name': 'Gói 1 tháng'},
    '3_months': {'days': 90, 'price': 80000, 'name': 'Gói 3 tháng'},
    '6_months': {'days': 180, 'price': 150000, 'name': 'Gói 6 tháng'},
    '1_year': {'days': 425, 'price': 280000, 'name': 'Gói 1 năm'}  # 365 + 60 ngày (tặng 2 tháng)
}

FREE_SCAN_LIMIT = 5  # Số lần quét miễn phí

def check_subscription(user_id):
    """
    Kiểm tra trạng thái subscription của user
    Returns: (has_active_sub: bool, plan_type: str, end_date: str)
    """
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT plan_type, end_date, is_active
            FROM subscriptions
            WHERE user_id = ? AND is_active = 1
            ORDER BY end_date DESC
            LIMIT 1
        """, (user_id,))
        row = c.fetchone()
        
        if not row:
            return False, None, None
        
        plan_type, end_date_str, is_active = row
        
        # Kiểm tra hết hạn
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d %H:%M:%S')
        except:
            return False, None, None
        
        now = datetime.now()
        
        if now > end_date:
            # Hết hạn -> vô hiệu hóa
            c.execute("UPDATE subscriptions SET is_active = 0 WHERE user_id = ?", (user_id,))
            conn.commit()
            return False, None, None
        
        return True, plan_type, end_date_str
    finally:
        conn.close()

def get_free_scan_count(user_id):
    """Lấy số lần quét miễn phí đã dùng"""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT scan_count FROM free_scan_counter WHERE user_id = ?", (user_id,))
        row = c.fetchone()
        return row[0] if row else 0
    finally:
        conn.close()

def increment_free_scan(user_id):
    """Tăng số lần quét miễn phí"""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO free_scan_counter (user_id, scan_count)
            VALUES (?, 1)
            ON CONFLICT(user_id) DO UPDATE SET scan_count = scan_count + 1
        """, (user_id,))
        conn.commit()
    finally:
        conn.close()

def reset_free_scan(user_id):
    """Reset counter khi user mua gói"""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM free_scan_counter WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()

def admin_activate_subscription(user_id, plan_type, admin_username):
    """
    Admin kích hoạt subscription cho user
    plan_type: '1_month', '3_months', '6_months', '1_year'
    """
    if plan_type not in PLAN_CONFIG:
        raise ValueError(f"Gói không hợp lệ: {plan_type}")
    
    config = PLAN_CONFIG[plan_type]
    now = datetime.now()
    end_date = now + timedelta(days=config['days'])
    
    conn = get_db()
    try:
        c = conn.cursor()
        
        # Vô hiệu hóa subscription cũ (nếu có)
        c.execute("UPDATE subscriptions SET is_active = 0 WHERE user_id = ?", (user_id,))
        
        # Xóa subscription cũ để tránh UNIQUE constraint
        c.execute("DELETE FROM subscriptions WHERE user_id = ?", (user_id,))
        
        # Tạo subscription mới
        c.execute("""
            INSERT INTO subscriptions (user_id, plan_type, start_date, end_date, is_active, activated_by)
            VALUES (?, ?, ?, ?, 1, ?)
        """, (user_id, plan_type, now.strftime('%Y-%m-%d %H:%M:%S'), end_date.strftime('%Y-%m-%d %H:%M:%S'), admin_username))
        
        # Reset free scan counter
        c.execute("DELETE FROM free_scan_counter WHERE user_id = ?", (user_id,))
        
        conn.commit()
        
        return {
            "plan_type": plan_type,
            "plan_name": config['name'],
            "start_date": now.strftime('%Y-%m-%d %H:%M:%S'),
            "end_date": end_date.strftime('%Y-%m-%d %H:%M:%S'),
            "price": config['price']
        }
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def admin_deactivate_subscription(user_id):
    """Admin hủy subscription của user"""
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("UPDATE subscriptions SET is_active = 0 WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()

def get_subscription_info(user_id, is_admin=False):
    """Lấy thông tin subscription của user"""
    if is_admin:
        return {
            "is_admin": True,
            "has_subscription": True,
            "plan_type": "admin",
            "plan_id": "admin",
            "plan_name": "Quản trị viên",
            "end_date": None,
            "free_scans_remaining": None
        }
    
    has_sub, plan_type, end_date = check_subscription(user_id)
    free_count = get_free_scan_count(user_id)
    
    plan_name = None
    if plan_type and plan_type in PLAN_CONFIG:
        plan_name = PLAN_CONFIG[plan_type]['name']
    
    return {
        "is_admin": False,
        "has_subscription": has_sub,
        "plan_type": plan_type,
        "plan_id": plan_type,  # Thêm plan_id cho frontend
        "plan_name": plan_name,
        "end_date": end_date,
        "free_scans_used": free_count,
        "free_scans_remaining": max(0, FREE_SCAN_LIMIT - free_count),
        "free_scan_limit": FREE_SCAN_LIMIT
    }

def check_scan_permission(user_id, is_admin):
    """
    Kiểm tra quyền quét mã
    Returns: (allowed: bool, error_response: dict or None)
    """
    if is_admin:
        return True, None
    
    has_sub, _, _ = check_subscription(user_id)
    
    if has_sub:
        return True, None
    
    # Không có subscription -> kiểm tra free scan
    free_count = get_free_scan_count(user_id)
    
    if free_count >= FREE_SCAN_LIMIT:
        return False, {
            "result": f"❌ Đã hết {FREE_SCAN_LIMIT} lượt quét miễn phí",
            "limit_reached": True,
            "free_scans_used": free_count,
            "message": f"Bạn đã sử dụng hết {FREE_SCAN_LIMIT} lượt quét miễn phí.\n\nVui lòng nâng cấp tài khoản Premium để tiếp tục sử dụng không giới hạn."
        }
    
    # Còn lượt free -> tăng counter
    increment_free_scan(user_id)
    return True, None

def check_feature_permission(user_id, is_admin, feature='create'):
    """
    Kiểm tra quyền truy cập tính năng (create, history)
    Returns: (allowed: bool, error_response: dict or None)
    """
    if is_admin:
        return True, None
    
    has_sub, _, _ = check_subscription(user_id)
    
    if has_sub:
        return True, None
    
    if feature == 'create':
        return False, {
            "status": "fail",
            "msg": "❌ Chức năng Tạo mã QR chỉ dành cho tài khoản Premium\n\nVui lòng nâng cấp tài khoản để sử dụng.",
            "require_subscription": True
        }
    elif feature == 'history':
        return False, {
            "status": "fail",
            "msg": "Lịch sử chỉ dành cho tài khoản Premium",
            "require_subscription": True
        }
    
    return False, {"status": "fail", "msg": "Không có quyền truy cập"}