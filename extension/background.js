/**
 * QR Checker Extension - Background Service Worker
 * Fetch ảnh cross-origin + decode QR
 * Phân tích URL: gọi backend VirusTotal (cần đăng nhập)
 */

importScripts('lib/jsQR.min.js');

const CONFIG = {
  API_BASE: 'https://smartqrchecker.pythonanywhere.com',
  CACHE_TTL: 10 * 60 * 1000
};

const resultCache = new Map();

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  handleMessage(request).then(resp => {
    sendResponse(resp);
  }).catch(err => {
    console.error('BG error:', err);
    sendResponse({ success: false, error: err.message });
  });
  return true;
});

async function handleMessage(request) {
  switch (request.action) {
    case 'scanImage':    return await handleScanImage(request.url);
    case 'checkQR':      {
      const data = await analyzeQR(request.data);
      // Đảm bảo luôn trả object hợp lệ
      if (!data || !data.level) {
        return { 
          success: true, 
          data: {
            status: 'info', type: 'text', level: 'info',
            message: '📝 Dữ liệu QR', 
            details: request.data
          }
        };
      }
      return { success: true, data };
    }
    case 'getSettings':  return await getSettings();
    case 'saveSettings': return await saveSettings(request.settings);
    case 'login':        return await handleLogin(request.username, request.password);
    case 'logout':       return await handleLogout();
    case 'checkLogin':   return await checkLoginStatus();
    default: return { success: false, error: 'Unknown action' };
  }
}

// ===================== LOGIN =====================

async function handleLogin(username, password) {
  try {
    const response = await fetch(`${CONFIG.API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
      credentials: 'include'
    });

    const text = await response.text();
    console.log('Login response:', response.status, text);

    let data;
    try { data = JSON.parse(text); } catch (e) {
      if (response.ok || response.redirected) {
        await chrome.storage.local.set({ loggedIn: true, username: username });
        return { success: true, username };
      }
      return { success: false, error: 'Server trả về không hợp lệ' };
    }

    if (
      response.ok ||
      data.status === 'ok' ||
      data.success === true ||
      data.msg === 'Đăng nhập thành công' ||
      data.message === 'Login successful'
    ) {
      await chrome.storage.local.set({
        loggedIn: true,
        username: username,
        isAdmin: data.is_admin || false
      });
      return { success: true, username };
    }

    return { success: false, error: data.msg || data.message || data.error || 'Sai tài khoản hoặc mật khẩu' };

  } catch (error) {
    console.error('Login error:', error);
    return { success: false, error: 'Không thể kết nối server. Kiểm tra backend đang chạy.' };
  }
}

async function handleLogout() {
  try {
    await fetch(`${CONFIG.API_BASE}/logout`, { credentials: 'include' });
  } catch (e) { /* ignore */ }
  await chrome.storage.local.set({ loggedIn: false, username: '', isAdmin: false });
  return { success: true };
}

async function checkLoginStatus() {
  const stored = await chrome.storage.local.get(['loggedIn', 'username']);
  return {
    success: true,
    loggedIn: stored.loggedIn || false,
    username: stored.username || ''
  };
}

async function getSession() {
  const status = await checkLoginStatus();
  return status.loggedIn ? status : null;
}

// ===================== SCAN IMAGE =====================

async function handleScanImage(imageUrl) {
  try {
    const response = await fetch(imageUrl);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const blob = await response.blob();
    const bitmap = await createImageBitmap(blob);

    const maxSize = 500;
    let w = bitmap.width, h = bitmap.height;
    if (w > maxSize || h > maxSize) {
      const r = Math.min(maxSize / w, maxSize / h);
      w = Math.floor(w * r); h = Math.floor(h * r);
    }

    const canvas = new OffscreenCanvas(w, h);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(bitmap, 0, 0, w, h);
    const imgData = ctx.getImageData(0, 0, w, h);

    const qr = jsQR(imgData.data, imgData.width, imgData.height);
    if (!qr) return { success: true, found: false };

    console.log('BG: QR found:', qr.data);

    const result = await analyzeQR(qr.data);
    return { success: true, found: true, qrData: qr.data, result: result || {
      status: 'info', type: 'text', level: 'info',
      message: '📝 Dữ liệu QR', details: qr.data
    }};

  } catch (error) {
    console.error('BG scanImage error:', error);
    return { success: false, error: error.message };
  }
}

// ===================== FILE / MACRO DETECTION =====================

const DEFINITE_MACRO_EXTENSIONS = ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm'];
const POSSIBLE_MACRO_EXTENSIONS = ['.doc', '.xls', '.ppt'];
const SAFE_DOC_EXTENSIONS = ['.docx', '.xlsx', '.pptx', '.pdf'];
const EXECUTABLE_EXTENSIONS = ['.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.jar', '.apk', '.dmg', '.scr', '.iso'];
const ARCHIVE_EXTENSIONS = ['.zip', '.rar', '.7z'];

const FILE_TYPE_NAMES = {
  '.docm': 'Word', '.xlsm': 'Excel', '.pptm': 'PowerPoint',
  '.dotm': 'Word Template', '.xltm': 'Excel Template', '.potm': 'PPT Template',
  '.doc': 'Word', '.xls': 'Excel', '.ppt': 'PowerPoint',
  '.docx': 'Word', '.xlsx': 'Excel', '.pptx': 'PowerPoint', '.pdf': 'PDF',
  '.zip': 'ZIP', '.rar': 'RAR', '.7z': '7Z', '.iso': 'ISO',
  '.exe': 'File thực thi', '.msi': 'File cài đặt', '.bat': 'Batch Script',
  '.cmd': 'Command Script', '.ps1': 'PowerShell', '.vbs': 'VBScript',
  '.js': 'JavaScript', '.jar': 'Java Archive', '.apk': 'Android App',
  '.dmg': 'macOS Image', '.scr': 'Screensaver'
};

function detectFileFromUrl(url) {
  try {
    const parsed = new URL(url);
    let path = parsed.pathname.toLowerCase().split('?')[0];
    
    const allExts = [
      ...DEFINITE_MACRO_EXTENSIONS, ...POSSIBLE_MACRO_EXTENSIONS,
      ...SAFE_DOC_EXTENSIONS, ...EXECUTABLE_EXTENSIONS, ...ARCHIVE_EXTENSIONS
    ];
    
    for (const ext of allExts) {
      if (path.endsWith(ext)) {
        return { ext, type: FILE_TYPE_NAMES[ext] || ext };
      }
    }
    
    for (const [, value] of parsed.searchParams) {
      const decoded = decodeURIComponent(value).toLowerCase();
      for (const ext of allExts) {
        if (decoded.endsWith(ext)) {
          return { ext, type: FILE_TYPE_NAMES[ext] || ext };
        }
      }
    }
  } catch (e) { }
  return null;
}

// ===================== PHÂN TÍCH QR =====================

async function analyzeQR(qrData) {
  if (!qrData || typeof qrData !== 'string') {
    return {
      status: 'info', type: 'text', level: 'info',
      message: '📝 Dữ liệu trống', details: ''
    };
  }

  // 1. WiFi
  if (qrData.toUpperCase().startsWith('WIFI:')) {
    const m = qrData.match(/S:([^;]*)/i);
    const ssid = m ? m[1] : '?';
    const enc = qrData.match(/T:([^;]*)/i);
    const encType = enc ? enc[1] : 'Không rõ';
    return {
      status: 'info', type: 'wifi', level: 'info',
      message: `📶 WiFi: ${ssid}`,
      details: `Bảo mật: ${encType}`
    };
  }

  // 2. mailto
  if (qrData.toLowerCase().startsWith('mailto:')) {
    const email = qrData.replace(/^mailto:/i, '').split('?')[0];
    return { status: 'info', type: 'email', level: 'info', message: `📧 Email: ${email}` };
  }

  // 3. tel
  if (qrData.toLowerCase().startsWith('tel:')) {
    const phone = qrData.replace(/^tel:/i, '');
    return { status: 'info', type: 'phone', level: 'info', message: `📞 Điện thoại: ${phone}` };
  }

  // 4. sms
  if (/^sms(to)?:/i.test(qrData)) {
    return { status: 'info', type: 'sms', level: 'info', message: '💬 Tin nhắn SMS' };
  }

  // 5. VietQR / Ngân hàng
  if (qrData.includes('vietqr.net') || /^00020101/.test(qrData)) {
    return {
      status: 'warning', type: 'bank', level: 'warning',
      message: '🏦 QR Ngân hàng / Thanh toán',
      details: '⚠️ Xác nhận người nhận trước khi chuyển tiền!'
    };
  }

  // 6. URL
  if (/^https?:\/\//i.test(qrData)) {
    const fileInfo = detectFileFromUrl(qrData);
    
    if (fileInfo) {
      return await analyzeFileURL(qrData, fileInfo);
    } else {
      return await analyzeURLBackend(qrData);
    }
  }

  // 7. Text thường
  return {
    status: 'info', type: 'text', level: 'info',
    message: '📝 Văn bản',
    details: qrData.length > 100 ? qrData.substring(0, 100) + '...' : qrData
  };
}

// ===================== PHÂN TÍCH FILE URL =====================

async function analyzeFileURL(qrData, fileInfo) {
  const isMacro = DEFINITE_MACRO_EXTENSIONS.includes(fileInfo.ext);
  const isPossibleMacro = POSSIBLE_MACRO_EXTENSIONS.includes(fileInfo.ext);
  const isExe = EXECUTABLE_EXTENSIONS.includes(fileInfo.ext);
  const isArchive = ARCHIVE_EXTENSIONS.includes(fileInfo.ext);

  let result;

  if (isMacro) {
    result = {
      status: 'danger', type: 'file', level: 'danger',
      message: `🚨 FILE CHỨA MACRO (${fileInfo.type})`,
      details: `⚠️ File ${fileInfo.type} có thể chứa mã độc Macro!\n` +
               `• KHÔNG bấm "Enable Macros" khi mở file\n` +
               `• Macro có thể tự động tải malware về máy`,
      fileInfo: { ext: fileInfo.ext, type: fileInfo.type, hasMacro: true, isExe: false }
    };
  } else if (isExe) {
    result = {
      status: 'danger', type: 'file', level: 'danger',
      message: `🚨 FILE THỰC THI (${fileInfo.type})`,
      details: `⚠️ Đây là file thực thi có thể chạy trực tiếp trên máy!\n` +
               `• Không tải file từ nguồn không tin cậy\n` +
               `• File có thể chứa virus, trojan, ransomware`,
      fileInfo: { ext: fileInfo.ext, type: fileInfo.type, hasMacro: false, isExe: true }
    };
  } else if (isPossibleMacro) {
    result = {
      status: 'warning', type: 'file', level: 'warning',
      message: `⚠️ File ${fileInfo.type} - Có thể chứa Macro`,
      details: `⚠️ File ${fileInfo.type} CÓ THỂ chứa Macro\n` +
               `• Cẩn thận khi mở, không bật Macro nếu không chắc\n` +
               `• Kiểm tra nguồn gốc file trước khi tải`,
      fileInfo: { ext: fileInfo.ext, type: fileInfo.type, hasMacro: true, isExe: false }
    };
  } else if (isArchive) {
    result = {
      status: 'warning', type: 'file', level: 'warning',
      message: `⚠️ File nén (${fileInfo.type})`,
      details: `⚠️ File nén có thể chứa file độc hại bên trong\n` +
               `• Quét file sau khi giải nén\n` +
               `• Không mở file .exe/.bat bên trong nếu không rõ nguồn gốc`,
      fileInfo: { ext: fileInfo.ext, type: fileInfo.type, hasMacro: false, isExe: false }
    };
  } else {
    result = {
      status: 'info', type: 'file', level: 'info',
      message: `📄 File tải về (${fileInfo.type})`,
      details: `File ${fileInfo.type} - Kiểm tra nguồn gốc trước khi tải`,
      fileInfo: { ext: fileInfo.ext, type: fileInfo.type, hasMacro: false, isExe: false }
    };
  }

  // Gọi backend nếu đã đăng nhập - FIX: dùng qr_data thay vì data
  try {
    const session = await getSession();
    if (session) {
      const resp = await fetch(`${CONFIG.API_BASE}/api/extension/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ qr_data: qrData })
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data.file_info && data.file_info.vt_file_result) {
          const vt = data.file_info.vt_file_result;
          if (vt.malicious > 0) {
            result.status = 'danger';
            result.level = 'danger';
            result.message = `🚫 MÃ ĐỘC! ${vt.malicious} engine phát hiện - ${fileInfo.type}`;
            result.details = `🔴 ${vt.malicious} engine phát hiện mã độc\n` +
                             `✅ ${vt.harmless || 0} engine sạch\n` +
                             `⚠️ KHÔNG TẢI FILE NÀY!`;
          } else if (vt.suspicious > 0) {
            result.details += `\n\n📊 VirusTotal: ${vt.suspicious} engine nghi ngờ, ${vt.harmless || 0} sạch`;
          } else if (vt.total > 0) {
            result.details += `\n\n📊 VirusTotal: ${vt.harmless || 0}/${vt.total} engine sạch`;
            if (!isMacro && !isExe) {
              result.status = 'safe';
              result.level = 'safe';
            }
          }
        }
      }
    }
  } catch (e) {
    console.log('VT check failed for file:', e);
  }

  return result;
}

// ===================== PHÂN TÍCH URL: CHỈ BACKEND =====================

async function analyzeURLBackend(url) {
  const loginStatus = await checkLoginStatus();

  if (!loginStatus.loggedIn) {
    return {
      status: 'login_required', type: 'url', level: 'warning',
      message: '🔐 Cần đăng nhập để kiểm tra URL',
      details: 'Đăng nhập để quét URL qua VirusTotal',
      url
    };
  }

  try {
    // FIX: dùng /api/extension/scan (không cần session) + đúng field qr_data
    const response = await fetch(`${CONFIG.API_BASE}/api/extension/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ qr_data: url }),
      credentials: 'include'
    });

    if (response.status === 401 || response.status === 403) {
      await chrome.storage.local.set({ loggedIn: false, username: '' });
      return {
        status: 'login_required', type: 'url', level: 'warning',
        message: '🔐 Phiên đăng nhập hết hạn',
        details: 'Vui lòng đăng nhập lại để kiểm tra',
        url
      };
    }

    if (!response.ok) {
      return {
        status: 'error', type: 'url', level: 'warning',
        message: '❌ Server lỗi',
        details: `HTTP ${response.status}`,
        url
      };
    }

    const data = await response.json();

    // Xử lý kết quả từ backend
    if (data.details) {
      const d = data.details;

      if (d.malicious > 0) {
        return {
          status: 'danger', type: 'url', level: 'danger',
          message: `🚫 NGUY HIỂM (${d.malicious} engine cảnh báo)`,
          details: `VirusTotal: ${d.clean || 0} sạch, ${d.suspicious || 0} nghi ngờ, ${d.malicious} độc hại`,
          url, source: 'virustotal'
        };
      }

      if (d.suspicious > 0) {
        return {
          status: 'warning', type: 'url', level: 'warning',
          message: `⚠️ Đáng ngờ (${d.suspicious} engine cảnh báo)`,
          details: `VirusTotal: ${d.clean || 0} sạch, ${d.suspicious} nghi ngờ`,
          url, source: 'virustotal'
        };
      }

      return {
        status: 'safe', type: 'url', level: 'safe',
        message: `✅ An toàn (${d.clean || 0} engine xác nhận)`,
        details: `VirusTotal: ${d.clean || 0} sạch, 0 nguy hiểm`,
        url, source: 'virustotal'
      };
    }

    // Kết quả khác từ backend
    if (data.result) {
      return {
        status: data.is_safe ? 'safe' : 'warning',
        type: 'url',
        level: data.is_safe ? 'safe' : 'warning',
        message: data.is_safe ? `✅ ${data.result}` : `⚠️ ${data.result}`,
        url, source: 'backend'
      };
    }

    return {
      status: 'error', type: 'url', level: 'warning',
      message: '❌ Không nhận được kết quả từ server',
      url
    };

  } catch (error) {
    console.error('Backend scan error:', error);
    return {
      status: 'error', type: 'url', level: 'warning',
      message: '❌ Không thể kết nối server',
      details: 'Kiểm tra backend đang chạy',
      url
    };
  }
}

// ===================== SETTINGS =====================

async function getSettings() {
  return new Promise(resolve => {
    chrome.storage.sync.get({
      enabled: true, hoverDelay: 2000, showTooltip: true, fileWarning: true
    }, s => {
      resolve({ success: true, data: s });
    });
  });
}

async function saveSettings(settings) {
  return new Promise(resolve => {
    chrome.storage.sync.set(settings, () => resolve({ success: true }));
  });
}