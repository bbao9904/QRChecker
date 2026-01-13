from flask import Blueprint, request, jsonify, session
from subscription import (
    PLAN_CONFIG,
    FREE_SCAN_LIMIT,
    check_subscription,
    get_subscription_info,
    admin_activate_subscription,
    admin_deactivate_subscription,
    get_free_scan_count
)
import sqlite3

def get_db():
    return sqlite3.connect('users.db')

subscription_bp = Blueprint('subscription', __name__)

@subscription_bp.route('/subscription/info', methods=['GET'])
def api_subscription_info():
    """Lấy thông tin subscription của user"""
    if "user_id" not in session:
        return jsonify({"status": "fail", "msg": "Chưa đăng nhập"}), 401
    
    user_id = session.get("user_id")
    is_admin = session.get("is_admin", False)
    
    info = get_subscription_info(user_id, is_admin)
    return jsonify({"status": "ok", **info})

@subscription_bp.route('/subscription/plans', methods=['GET'])
def api_get_plans():
    """Lấy danh sách các gói"""
    plans = []
    for key, config in PLAN_CONFIG.items():
        plans.append({
            "id": key,
            "name": config['name'],
            "days": config['days'],
            "price": config['price']
        })
    return jsonify({"status": "ok", "plans": plans})

# ===== ADMIN APIs =====
@subscription_bp.route('/admin/user/<int:user_id>/subscription', methods=['GET'])
def admin_get_user_subscription(user_id):
    """Admin xem subscription của user"""
    if not session.get("is_admin"):
        return jsonify({"status": "fail", "msg": "Không có quyền"}), 403
    
    has_sub, plan_type, end_date = check_subscription(user_id)
    free_count = get_free_scan_count(user_id)
    
    plan_name = None
    if plan_type and plan_type in PLAN_CONFIG:
        plan_name = PLAN_CONFIG[plan_type]['name']
    
    return jsonify({
        "status": "ok",
        "has_subscription": has_sub,
        "plan_type": plan_type,
        "plan_name": plan_name,
        "end_date": end_date,
        "free_scans_used": free_count,
        "free_scan_limit": FREE_SCAN_LIMIT
    })

@subscription_bp.route('/admin/user/<int:user_id>/subscription/activate', methods=['POST'])
def admin_activate_user_subscription(user_id):
    """Admin kích hoạt subscription cho user"""
    if not session.get("is_admin"):
        return jsonify({"status": "fail", "msg": "Không có quyền"}), 403
    
    data = request.get_json()
    plan_type = data.get('plan_type')
    
    if plan_type not in PLAN_CONFIG:
        return jsonify({"status": "fail", "msg": f"Gói không hợp lệ. Chọn: {', '.join(PLAN_CONFIG.keys())}"}), 400
    
    # Kiểm tra user tồn tại
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user_row = c.fetchone()
    conn.close()
    
    if not user_row:
        return jsonify({"status": "fail", "msg": "Không tìm thấy user"}), 404
    
    try:
        admin_username = session.get("username", "admin")
        result = admin_activate_subscription(user_id, plan_type, admin_username)
        
        return jsonify({
            "status": "ok",
            "msg": f"✅ Đã kích hoạt {result['plan_name']} cho {user_row[0]}",
            **result
        })
    except Exception as e:
        return jsonify({"status": "fail", "msg": f"Lỗi: {str(e)}"}), 500

@subscription_bp.route('/admin/user/<int:user_id>/subscription/deactivate', methods=['POST'])
def admin_deactivate_user_subscription(user_id):
    """Admin hủy subscription của user"""
    if not session.get("is_admin"):
        return jsonify({"status": "fail", "msg": "Không có quyền"}), 403
    
    try:
        admin_deactivate_subscription(user_id)
        return jsonify({"status": "ok", "msg": "✅ Đã hủy subscription"})
    except Exception as e:
        return jsonify({"status": "fail", "msg": f"Lỗi: {str(e)}"}), 500