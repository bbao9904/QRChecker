/**
 * QR Checker Extension - Content Script
 * Hover ảnh → local scan, nếu cross-origin thì background fetch
 */

(function() {
  'use strict';

  if (window.__qrCheckerLoaded) return;
  window.__qrCheckerLoaded = true;

  let settings = { enabled: true, hoverDelay: 2000, showTooltip: true };
  let hoverTimer = null;
  let currentTooltip = null;
  let tooltipTimer = null;
  let processedImages = new WeakSet();
  let scanCache = new Map();

  loadSettings();

  function loadSettings() {
    try {
      chrome.runtime.sendMessage({ action: 'getSettings' }, (response) => {
        if (chrome.runtime.lastError) return;
        if (response && response.success) {
          settings = { ...settings, ...response.data };
        }
        if (settings.enabled) init();
      });
    } catch (e) {
      init();
    }
  }

  function init() {
    scanExistingImages();
    observeNewImages();
    console.log('🔍 QR Checker đã kích hoạt');
  }

  function scanExistingImages() {
    document.querySelectorAll('img, canvas').forEach(attachHoverListener);
  }

  function observeNewImages() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach(m => {
        m.addedNodes.forEach(node => {
          if (node.nodeName === 'IMG' || node.nodeName === 'CANVAS') {
            attachHoverListener(node);
          } else if (node.querySelectorAll) {
            node.querySelectorAll('img, canvas').forEach(attachHoverListener);
          }
        });
      });
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  function attachHoverListener(el) {
    if (processedImages.has(el)) return;
    processedImages.add(el);
    el.addEventListener('mouseenter', onMouseEnter);
    el.addEventListener('mouseleave', onMouseLeave);
  }

  function onMouseEnter(e) {
    if (!settings.enabled) return;
    const el = e.target;
    const rect = el.getBoundingClientRect();
    if (rect.width < 50 || rect.height < 50) return;

    showWaitingIndicator(el);
    hoverTimer = setTimeout(() => processImage(el), settings.hoverDelay);
  }

  function onMouseLeave(e) {
    if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; }
    hideWaitingIndicator(e.target);
  }

  // ===================== PROCESS IMAGE =====================

  async function processImage(element) {
    hideWaitingIndicator(element);
    showTooltip(element, { status: 'loading', message: '🔍 Đang quét mã QR...' });

    const localResult = tryLocalScan(element);

    if (localResult !== null) {
      console.log('QR Checker: Local scan OK');
      handleScanResult(element, localResult);
      return;
    }

    console.log('QR Checker: Cross-origin, chuyển sang background fetch...');
    await backgroundScan(element);
  }

  function tryLocalScan(element) {
    try {
      let imgData;

      if (element.tagName === 'CANVAS') {
        const ctx = element.getContext('2d');
        imgData = ctx.getImageData(0, 0, element.width, element.height);
      } else if (element.tagName === 'IMG') {
        if (!element.complete || !element.naturalWidth) return null;

        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        const maxSize = 500;
        let w = element.naturalWidth, h = element.naturalHeight;
        if (w > maxSize || h > maxSize) {
          const r = Math.min(maxSize / w, maxSize / h);
          w = Math.floor(w * r); h = Math.floor(h * r);
        }
        canvas.width = w;
        canvas.height = h;
        ctx.drawImage(element, 0, 0, w, h);
        imgData = ctx.getImageData(0, 0, w, h);
      } else {
        return null;
      }

      if (typeof jsQR === 'undefined') return null;

      const qr = jsQR(imgData.data, imgData.width, imgData.height);
      return qr ? { found: true, qrData: qr.data } : { found: false };

    } catch (e) {
      console.log('QR Checker: Local scan failed (cross-origin):', e.message);
      return null;
    }
  }

  async function backgroundScan(element) {
    let imageUrl = null;

    if (element.tagName === 'IMG') {
      imageUrl = element.src;
    } else if (element.tagName === 'CANVAS') {
      try {
        imageUrl = element.toDataURL('image/png');
      } catch (e) { /* tainted */ }
    }

    if (!imageUrl) {
      showTooltip(element, {
        status: 'warning', level: 'warning',
        message: '⚠️ Không thể đọc ảnh này'
      });
      autoHide(3000);
      return;
    }

    if (scanCache.has(imageUrl)) {
      showTooltip(element, scanCache.get(imageUrl));
      return;
    }

    try {
      chrome.runtime.sendMessage({ action: 'scanImage', url: imageUrl }, (resp) => {
        if (chrome.runtime.lastError) {
          showTooltip(element, { status: 'error', level: 'warning', message: '❌ Extension lỗi, thử reload trang' });
          autoHide(3000);
          return;
        }

        if (!resp || !resp.success) {
          showTooltip(element, { status: 'warning', level: 'warning', message: '⚠️ Không đọc được ảnh', details: resp?.error || '' });
          autoHide(3000);
          return;
        }

        if (!resp.found) {
          showTooltip(element, { status: 'none', level: 'info', message: '📷 Không phải mã QR' });
          autoHide(3000);
          return;
        }

        console.log('QR Checker: Background scan found:', resp.qrData);
        scanCache.set(imageUrl, resp.result);
        showTooltip(element, resp.result);
      });
    } catch (e) {
      showTooltip(element, { status: 'error', level: 'warning', message: '❌ Extension lỗi' });
      autoHide(3000);
    }
  }

  function handleScanResult(element, localResult) {
    if (!localResult.found) {
      showTooltip(element, { status: 'none', level: 'info', message: '📷 Không phải mã QR' });
      autoHide(3000);
      return;
    }

    if (scanCache.has(localResult.qrData)) {
      showTooltip(element, scanCache.get(localResult.qrData));
      return;
    }

    showTooltip(element, { status: 'loading', message: '🔍 Đang phân tích...' });

    try {
      chrome.runtime.sendMessage({ action: 'checkQR', data: localResult.qrData }, (resp) => {
        if (chrome.runtime.lastError) {
          showTooltip(element, { status: 'error', level: 'warning', message: '❌ Extension lỗi' });
          return;
        }
        if (resp && resp.success) {
          scanCache.set(localResult.qrData, resp.data);
          showTooltip(element, resp.data);
        }
      });
    } catch (e) {
      showTooltip(element, { status: 'error', level: 'warning', message: '❌ Lỗi phân tích' });
    }
  }

  // ===================== AUTO HIDE =====================

  function autoHide(ms) {
    if (tooltipTimer) clearTimeout(tooltipTimer);
    tooltipTimer = setTimeout(() => {
      hideTooltip();
    }, ms);
  }

  // ===================== TOOLTIP =====================

  function showWaitingIndicator(el) {
    hideWaitingIndicator(el);
    const indicator = document.createElement('div');
    indicator.className = 'qrc-waiting-indicator';
    indicator.innerHTML = '<div class="qrc-waiting-ring"></div><span>Chuẩn bị quét...</span>';
    positionTooltip(indicator, el);
    document.body.appendChild(indicator);
    el.__qrcWaiting = indicator;
  }

  function hideWaitingIndicator(el) {
    if (el && el.__qrcWaiting) { el.__qrcWaiting.remove(); delete el.__qrcWaiting; }
  }

  function showTooltip(element, result) {
    hideTooltip();
    if (!settings.showTooltip && result.status !== 'danger') return;

    const tooltip = document.createElement('div');
    tooltip.className = `qrc-tooltip qrc-${result.level || result.status}`;

    let content = `<div class="qrc-tooltip-header">${result.message}</div>`;

    // Chi tiết
    if (result.details && typeof result.details === 'string') {
      const lines = result.details.split('\n');
      content += '<div class="qrc-tooltip-detail">';
      lines.forEach(line => {
        content += `<div style="margin:2px 0">${line}</div>`;
      });
      content += '</div>';
    }

    // Nguồn kiểm tra
    if (result.source) {
      const sourceLabel = result.source === 'virustotal' ? '🛡️ VirusTotal'
                        : result.source === 'backend' ? '🌐 Server'
                        : '📱 Offline';
      content += `<div class="qrc-tooltip-source">Nguồn: ${sourceLabel}</div>`;
    }

    // Gợi ý đăng nhập
    if (result.extra) {
      content += `<div class="qrc-tooltip-extra">${result.extra}</div>`;
    }

    // URL - NẾU AN TOÀN thì cho click để mở, NẾU NGUY HIỂM thì chỉ hiển thị
    if (result.url) {
      if (result.level === 'safe' || result.level === 'info') {
        // An toàn → link clickable
        content += `<a class="qrc-tooltip-url qrc-url-link" href="${escapeHtml(result.url)}" target="_blank" rel="noopener noreferrer" title="Click để mở: ${escapeHtml(result.url)}">🔗 ${truncate(result.url, 55)}</a>`;
      } else if (result.level === 'warning') {
        // Cảnh báo → link nhưng có xác nhận
        content += `<a class="qrc-tooltip-url qrc-url-warn" href="#" data-url="${escapeHtml(result.url)}" title="Click để mở (cẩn thận!)">⚠️ ${truncate(result.url, 55)}</a>`;
      } else {
        // Nguy hiểm → không cho click
        content += `<div class="qrc-tooltip-url qrc-url-danger">🚫 ${truncate(result.url, 55)}</div>`;
      }
    }

    content += `<button class="qrc-tooltip-close" onclick="this.parentElement.remove()">×</button>`;

    tooltip.innerHTML = content;

    // Xử lý click URL cảnh báo (xác nhận trước)
    const warnLink = tooltip.querySelector('.qrc-url-warn');
    if (warnLink) {
      warnLink.addEventListener('click', (e) => {
        e.preventDefault();
        const url = warnLink.getAttribute('data-url');
        if (confirm(`⚠️ URL này có dấu hiệu đáng ngờ!\n\n${url}\n\nBạn vẫn muốn mở?`)) {
          window.open(url, '_blank', 'noopener,noreferrer');
        }
      });
    }

    // Hover vào tooltip → không tự ẩn
    tooltip.addEventListener('mouseenter', () => {
      if (tooltipTimer) { clearTimeout(tooltipTimer); tooltipTimer = null; }
    });

    // Rời tooltip → bắt đầu đếm lại
    tooltip.addEventListener('mouseleave', () => {
      const duration = result.level === 'danger' ? 30000 : 8000;
      autoHide(duration);
    });

    positionTooltip(tooltip, element);
    document.body.appendChild(tooltip);
    currentTooltip = tooltip;

    // Auto hide - thời gian dài hơn
    if (result.status !== 'loading') {
      let duration;
      if (result.level === 'danger') {
        duration = 60000;     // Nguy hiểm: 60s
      } else if (result.level === 'warning') {
        duration = 30000;     // Cảnh báo: 30s
      } else if (result.level === 'safe' && result.url) {
        duration = 20000;     // An toàn có URL: 20s (để user kịp click)
      } else if (result.level === 'info') {
        duration = 10000;     // Info: 10s
      } else {
        duration = 8000;      // Mặc định: 8s
      }
      autoHide(duration);
    }
  }

  function hideTooltip() {
    if (tooltipTimer) { clearTimeout(tooltipTimer); tooltipTimer = null; }
    if (currentTooltip) { currentTooltip.remove(); currentTooltip = null; }
  }

  function positionTooltip(el, target) {
    const rect = target.getBoundingClientRect();
    el.style.position = 'absolute';
    el.style.left = `${rect.left + window.scrollX + rect.width / 2}px`;
    el.style.top = `${rect.top + window.scrollY - 10}px`;
    el.style.transform = 'translate(-50%, -100%)';
    el.style.zIndex = '2147483647';
  }

  function truncate(s, n) { return s && s.length > n ? s.slice(0, n) + '...' : (s || ''); }

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

})();