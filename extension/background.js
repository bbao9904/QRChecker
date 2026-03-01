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
  handleMessage(request).then(sendResponse).catch(err => {
    console.error('BG error:', err);
    sendResponse({ success: false, error: err.message });
  });
  return true;
});

async function handleMessage(request) {
  switch (request.action) {
    case 'scanImage':    return await handleScanImage(request.url);
    case 'checkQR':      return { success: true, data: await analyzeQR(request.data) };
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
    loggedIn: stored.loggedIn || false,
    username: stored.username || ''
  };
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
    return { success: true, found: true, qrData: qr.data, result };

  } catch (error) {
    console.error('BG scanImage error:', error);
    return { success: false, error: error.message };
  }
}

// ===================== PHÂN TÍCH QR =====================

async function analyzeQR(qrData) {
  // Cache
  const cached = resultCache.get(qrData);
  if (cached && Date.now() - cached.ts < CONFIG.CACHE_TTL) return cached.result;

  let result;

  // WiFi
  if (qrData.toUpperCase().startsWith('WIFI:')) {
    const m = qrData.match(/S:([^;]*)/i);
    const ssid = m ? m[1] : '?';
    const enc = qrData.match(/T:([^;]*)/i);
    const encType = enc ? enc[1] : 'Không rõ';
    result = {
      status: 'info', type: 'wifi', level: 'info',
      message: `📶 WiFi: ${ssid}`,
      details: `Bảo mật: ${encType}`
    };
  }
  // Email
  else if (qrData.toLowerCase().startsWith('mailto:')) {
    const email = qrData.replace(/^mailto:/i, '').split('?')[0];
    result = { status: 'info', type: 'email', level: 'info', message: `📧 Email: ${email}` };
  }
  // Phone
  else if (qrData.toLowerCase().startsWith('tel:')) {
    const phone = qrData.replace(/^tel:/i, '');
    result = { status: 'info', type: 'phone', level: 'info', message: `📞 Điện thoại: ${phone}` };
  }
  // SMS
  else if (/^sms(to)?:/i.test(qrData)) {
    result = { status: 'info', type: 'sms', level: 'info', message: '💬 Tin nhắn SMS' };
  }
  // VietQR / Ngân hàng
  else if (qrData.includes('vietqr.net') || /^00020101/.test(qrData)) {
    result = {
      status: 'warning', type: 'bank', level: 'warning',
      message: '🏦 QR Ngân hàng / Thanh toán',
      details: '⚠️ Xác nhận người nhận trước khi chuyển tiền!'
    };
  }
  // URL → gọi backend
  else if (/^https?:\/\//i.test(qrData)) {
    result = await analyzeURLBackend(qrData);
  }
  // Văn bản thuần
  else {
    result = {
      status: 'info', type: 'text', level: 'info',
      message: '📝 Văn bản thuần',
      details: qrData.length > 80 ? qrData.slice(0, 80) + '...' : qrData
    };
  }

  resultCache.set(qrData, { ts: Date.now(), result });
  return result;
}

// ===================== PHÂN TÍCH URL: CHỈ BACKEND =====================

async function analyzeURLBackend(url) {
  // Kiểm tra đăng nhập
  const loginStatus = await checkLoginStatus();

  if (!loginStatus.loggedIn) {
    return {
      status: 'login_required', type: 'url', level: 'warning',
      message: '🔐 Cần đăng nhập để kiểm tra URL',
      details: 'Đăng nhập để quét URL qua VirusTotal',
      url
    };
  }

  // Gọi backend /scan
  try {
    const response = await fetch(`${CONFIG.API_BASE}/scan`, {
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
    chrome.storage.sync.get({ enabled: true, hoverDelay: 2000, showTooltip: true }, s => {
      resolve({ success: true, data: s });
    });
  });
}

async function saveSettings(settings) {
  return new Promise(resolve => {
    chrome.storage.sync.set(settings, () => resolve({ success: true }));
  });
}