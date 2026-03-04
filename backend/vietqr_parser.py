"""
VietQR / EMV QR Code Parser
Parse thông tin ngân hàng từ mã QR chuẩn EMVCo
"""
import requests
# Danh sách BIN ngân hàng Việt Nam
VIETNAM_BANKS = {
    "970415": {"name": "VietinBank", "short": "CTG", "full": "Ngân hàng TMCP Công Thương Việt Nam"},
    "970436": {"name": "Vietcombank", "short": "VCB", "full": "Ngân hàng TMCP Ngoại Thương Việt Nam"},
    "970418": {"name": "BIDV", "short": "BIDV", "full": "Ngân hàng TMCP Đầu Tư và Phát Triển Việt Nam"},
    "970405": {"name": "Agribank", "short": "AGR", "full": "Ngân hàng Nông nghiệp và Phát triển Nông thôn"},
    "970448": {"name": "OCB", "short": "OCB", "full": "Ngân hàng TMCP Phương Đông"},
    "970422": {"name": "MB Bank", "short": "MB", "full": "Ngân hàng TMCP Quân Đội"},
    "970407": {"name": "Techcombank", "short": "TCB", "full": "Ngân hàng TMCP Kỹ Thương Việt Nam"},
    "970416": {"name": "ACB", "short": "ACB", "full": "Ngân hàng TMCP Á Châu"},
    "970432": {"name": "VPBank", "short": "VPB", "full": "Ngân hàng TMCP Việt Nam Thịnh Vượng"},
    "970423": {"name": "TPBank", "short": "TPB", "full": "Ngân hàng TMCP Tiên Phong"},
    "970437": {"name": "HDBank", "short": "HDB", "full": "Ngân hàng TMCP Phát Triển TP.HCM"},
    "970431": {"name": "Eximbank", "short": "EIB", "full": "Ngân hàng TMCP Xuất Nhập Khẩu Việt Nam"},
    "970443": {"name": "SHB", "short": "SHB", "full": "Ngân hàng TMCP Sài Gòn - Hà Nội"},
    "970403": {"name": "Sacombank", "short": "STB", "full": "Ngân hàng TMCP Sài Gòn Thương Tín"},
    "970441": {"name": "VIB", "short": "VIB", "full": "Ngân hàng TMCP Quốc Tế Việt Nam"},
    "970449": {"name": "LPBank", "short": "LPB", "full": "Ngân hàng TMCP Bưu Điện Liên Việt"},
    "970454": {"name": "VietCapital Bank", "short": "BVB", "full": "Ngân hàng TMCP Bản Việt"},
    "970429": {"name": "SCB", "short": "SCB", "full": "Ngân hàng TMCP Sài Gòn"},
    "970414": {"name": "OceanBank", "short": "OJB", "full": "Ngân hàng TNHH MTV Đại Dương"},
    "970426": {"name": "MSB", "short": "MSB", "full": "Ngân hàng TMCP Hàng Hải Việt Nam"},
    "970427": {"name": "VietABank", "short": "VAB", "full": "Ngân hàng TMCP Việt Á"},
    "970419": {"name": "NCB", "short": "NCB", "full": "Ngân hàng TMCP Quốc Dân"},
    "970406": {"name": "DongA Bank", "short": "DAB", "full": "Ngân hàng TMCP Đông Á"},
    "970438": {"name": "BaoViet Bank", "short": "BVB2", "full": "Ngân hàng TMCP Bảo Việt"},
    "970440": {"name": "SeABank", "short": "SSB", "full": "Ngân hàng TMCP Đông Nam Á"},
    "970410": {"name": "ABBANK", "short": "ABB", "full": "Ngân hàng TMCP An Bình"},
    "970400": {"name": "SaigonBank", "short": "SGB", "full": "Ngân hàng TMCP Sài Gòn Công Thương"},
    "970412": {"name": "PVcomBank", "short": "PVB", "full": "Ngân hàng TMCP Đại Chúng Việt Nam"},
    "970421": {"name": "VRB", "short": "VRB", "full": "Ngân hàng Liên Doanh Việt - Nga"},
    "970430": {"name": "PGBank", "short": "PGB", "full": "Ngân hàng TMCP Xăng Dầu Petrolimex"},
    "970433": {"name": "VietBank", "short": "VBB", "full": "Ngân hàng TMCP Việt Nam Thương Tín"},
    "970409": {"name": "Bac A Bank", "short": "BAB", "full": "Ngân hàng TMCP Bắc Á"},
    "970452": {"name": "KienLong Bank", "short": "KLB", "full": "Ngân hàng TMCP Kiên Long"},
    "970442": {"name": "Hong Leong VN", "short": "HLBVN", "full": "Ngân hàng TNHH MTV Hong Leong Việt Nam"},
    "970424": {"name": "Shinhan VN", "short": "SHBVN", "full": "Ngân hàng TNHH MTV Shinhan Việt Nam"},
    "970434": {"name": "Indovina Bank", "short": "IVB", "full": "Ngân hàng TNHH Indovina"},
    "970446": {"name": "COOP Bank", "short": "COOPBANK", "full": "Ngân hàng Hợp tác xã Việt Nam"},
    "970457": {"name": "Woori Bank", "short": "WVN", "full": "Ngân hàng TNHH MTV Woori Việt Nam"},
    "970462": {"name": "KBank", "short": "KBV", "full": "Ngân hàng Đại chúng TNHH Kasikornbank"},
    "970458": {"name": "UOB VN", "short": "UOBVN", "full": "Ngân hàng United Overseas Bank VN"},
    "970408": {"name": "GPBank", "short": "GPB", "full": "Ngân hàng TNHH MTV Dầu Khí Toàn Cầu"},
    "970439": {"name": "Public Bank VN", "short": "PBVN", "full": "Ngân hàng TNHH MTV Public Việt Nam"},
    "970428": {"name": "Nam A Bank", "short": "NAB", "full": "Ngân hàng TMCP Nam Á"},
}

# Ví điện tử
EWALLETS = {
    "546034": {"name": "MoMo", "short": "MOMO", "full": "Ví điện tử MoMo"},
    "546035": {"name": "ZaloPay", "short": "ZALO", "full": "Ví điện tử ZaloPay"},
    "546036": {"name": "VNPay", "short": "VNPAY", "full": "Ví điện tử VNPay"},
}

# Gộp tất cả
ALL_PROVIDERS = {**VIETNAM_BANKS, **EWALLETS}


def parse_tlv(data):
    """Parse TLV (Tag-Length-Value) format theo chuẩn EMVCo"""
    result = {}
    i = 0
    while i < len(data) - 3:
        try:
            tag = data[i:i+2]
            length = int(data[i+2:i+4])
            value = data[i+4:i+4+length]
            result[tag] = value
            i = i + 4 + length
        except (ValueError, IndexError):
            break
    return result


def mask_account(account):
    """Mask số tài khoản, chỉ hiện 4 số cuối"""
    if not account:
        return None
    if len(account) <= 4:
        return account
    return '*' * (len(account) - 4) + account[-4:]


def lookup_account_name(bank_bin, account_number):
    """
    Tra cứu tên chủ tài khoản qua API miễn phí
    Sử dụng API của các ngân hàng / VietQR
    """
    if not bank_bin or not account_number:
        return None
    
    # Cách 1: API Vietcombank (qua casso.vn hoặc sepay.vn - miễn phí với giới hạn)
    # Cách 2: API VietQR.org (cần đăng ký)
    # Cách 3: API mbbank-lookup (phổ biến trong cộng đồng VN)
    
    try:
        # Thử API miễn phí từ vietqr.net
        resp = requests.post(
            "https://api.vietqr.io/v2/lookup",
            json={
                "bin": bank_bin,
                "accountNumber": account_number
            },
            headers={
                "Content-Type": "application/json",
                "x-client-id": "",  # Để trống nếu dùng free tier
                "x-api-key": ""
            },
            timeout=10
        )
        
        if resp.status_code == 200:
            data = resp.json()
            if data.get("code") == "00" and data.get("data"):
                return data["data"].get("accountName")
    except Exception as e:
        print(f"Account lookup error (vietqr): {e}")
    
    try:
        # Fallback: API sepay.vn (miễn phí, không cần key)
        resp = requests.post(
            "https://my.sepay.vn/userapi/bank/check",
            json={
                "bank_code": bank_bin,
                "account_number": account_number
            },
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == 200 and data.get("data"):
                return data["data"].get("account_name")
    except Exception as e:
        print(f"Account lookup error (sepay): {e}")
    
    return None


def parse_emv_qr(raw):
    """
    Parse EMV QR Code (chuẩn VietQR / NAPAS)
    
    Cấu trúc EMVCo QR:
    - ID 00: Payload Format Indicator (luôn là "01")
    - ID 01: Point of Initiation Method
    - ID 26-51: Merchant Account Information
    - ID 38: VietQR (NAPAS) - chứa BIN ngân hàng + STK
    - ID 52: Merchant Category Code
    - ID 53: Transaction Currency (704 = VND)
    - ID 54: Transaction Amount
    - ID 58: Country Code (VN)
    - ID 59: Merchant Name
    - ID 60: Merchant City
    - ID 62: Additional Data Field (chứa nội dung CK)
    - ID 63: CRC checksum
    """
    if not isinstance(raw, str) or not raw.startswith('00020101'):
        return None
    
    result = {
        "bank_name": None,
        "bank_short": None,
        "bank_full": None,
        "bank_bin": None,
        "account_number": None,
        "account_masked": None,
        "account_name": None,
        "amount": None,
        "description": None,
        "currency": None,
        "country": None,
        "merchant_name": None,
        "merchant_city": None,
        "merchant_category": None,
        "is_dynamic": False,
    }
    
    try:
        tlv = parse_tlv(raw)
        
        # ID 01: Point of Initiation (11 = static, 12 = dynamic)
        if '01' in tlv:
            result["is_dynamic"] = tlv['01'] == '12'
        
        # ID 52: Merchant Category Code
        if '52' in tlv:
            result["merchant_category"] = tlv['52']
        
        # ID 53: Currency (704 = VND)
        if '53' in tlv:
            code = tlv['53']
            result["currency"] = "VND" if code == "704" else code
        
        # ID 54: Amount
        if '54' in tlv:
            result["amount"] = tlv['54']
        
        # ID 58: Country
        if '58' in tlv:
            result["country"] = tlv['58']
        
        # ID 59: Merchant Name
        if '59' in tlv:
            result["merchant_name"] = tlv['59']
        
        # ID 60: Merchant City
        if '60' in tlv:
            result["merchant_city"] = tlv['60']
        
        # ID 62: Additional Info
        if '62' in tlv:
            sub62 = parse_tlv(tlv['62'])
            if '08' in sub62:
                result["description"] = sub62['08']
            elif '05' in sub62:
                result["description"] = sub62['05']
        
        # ID 38: VietQR (NAPAS) - ưu tiên cao nhất
        bank_found = False
        if '38' in tlv:
            sub38 = parse_tlv(tlv['38'])
            if '01' in sub38:
                sub01 = parse_tlv(sub38['01'])
                if '00' in sub01:
                    bin_code = sub01['00']
                    result["bank_bin"] = bin_code
                    bank = ALL_PROVIDERS.get(bin_code)
                    if bank:
                        result["bank_name"] = bank["name"]
                        result["bank_short"] = bank["short"]
                        result["bank_full"] = bank["full"]
                        bank_found = True
                if '01' in sub01:
                    result["account_number"] = sub01['01']
        
        # Fallback: tìm trong ID 26-51
        if not bank_found:
            for mid in range(26, 52):
                mid_str = f"{mid:02d}"
                if mid_str in tlv and mid_str != '38':
                    sub = parse_tlv(tlv[mid_str])
                    if '01' in sub:
                        inner = parse_tlv(sub['01'])
                        if '00' in inner:
                            bin_code = inner['00']
                            result["bank_bin"] = bin_code
                            bank = ALL_PROVIDERS.get(bin_code)
                            if bank:
                                result["bank_name"] = bank["name"]
                                result["bank_short"] = bank["short"]
                                result["bank_full"] = bank["full"]
                                bank_found = True
                        if '01' in inner and not result["account_number"]:
                            result["account_number"] = inner['01']
                    if bank_found:
                        break
        
        # Tra cứu tên chủ tài khoản
        if result["bank_bin"] and result["account_number"]:
            account_name = lookup_account_name(result["bank_bin"], result["account_number"])
            if account_name:
                result["account_name"] = account_name
        
        # Mask STK
        result["account_masked"] = mask_account(result["account_number"])
        
        # Xóa account_number gốc (bảo mật)
        del result["account_number"]
        
        # Lọc bỏ None
        return {k: v for k, v in result.items() if v is not None}
        
    except Exception as e:
        print(f"EMV parse error: {e}")
        return None


def is_bank_qr(raw):
    """Kiểm tra nhanh có phải QR ngân hàng không"""
    if not isinstance(raw, str):
        return False
    return 'vietqr.net' in raw or raw.startswith('00020101')