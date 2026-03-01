/**
 * QR Checker Extension - Popup Script với đăng nhập
 */

document.addEventListener('DOMContentLoaded', () => {
  const loginSection = document.getElementById('loginSection');
  const userSection = document.getElementById('userSection');
  const loginForm = document.getElementById('loginForm');
  const loginError = document.getElementById('loginError');
  const loginBtn = document.getElementById('loginBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  const userName = document.getElementById('userName');
  const modeIndicator = document.getElementById('modeIndicator');
  const statusDiv = document.getElementById('status');

  const enabledCheckbox = document.getElementById('enabled');
  const hoverDelaySlider = document.getElementById('hoverDelay');
  const delayValue = document.getElementById('delayValue');
  const showTooltipCheckbox = document.getElementById('showTooltip');

  checkLoginStatus();
  loadSettings();

  async function checkLoginStatus() {
    try {
      const response = await chrome.runtime.sendMessage({ action: 'checkLogin' });
      if (response && response.loggedIn) {
        showLoggedIn(response.username);
      } else {
        showLoggedOut();
      }
    } catch (e) {
      showLoggedOut();
    }
  }

  function showLoggedIn(name) {
    loginSection.classList.remove('active');
    userSection.classList.add('active');
    userName.textContent = name;
    modeIndicator.className = 'mode-indicator online';
    modeIndicator.textContent = '🛡️ Online - Quét VirusTotal';
    statusDiv.textContent = '✅ Sẵn sàng';
  }

  function showLoggedOut() {
    loginSection.classList.add('active');
    userSection.classList.remove('active');
    modeIndicator.className = 'mode-indicator offline';
    modeIndicator.textContent = '🔐 Đăng nhập để kiểm tra URL';
    statusDiv.textContent = '⚠️ Chưa đăng nhập';
  }

  function loadSettings() {
    chrome.runtime.sendMessage({ action: 'getSettings' }, (response) => {
      if (response && response.success) {
        const s = response.data;
        enabledCheckbox.checked = s.enabled;
        hoverDelaySlider.value = s.hoverDelay;
        delayValue.textContent = (s.hoverDelay / 1000) + 's';
        showTooltipCheckbox.checked = s.showTooltip;
      }
    });
  }

  // Login
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const user = document.getElementById('username').value.trim();
    const pass = document.getElementById('password').value;
    if (!user || !pass) { showError('Vui lòng nhập đầy đủ'); return; }

    loginBtn.textContent = 'Đang đăng nhập...';
    loginBtn.disabled = true;
    hideError();

    try {
      const resp = await chrome.runtime.sendMessage({ action: 'login', username: user, password: pass });
      if (resp && resp.success) {
        showLoggedIn(resp.username);
        statusDiv.textContent = '✅ Đăng nhập thành công';
        statusDiv.classList.add('saved');
        setTimeout(() => { statusDiv.textContent = '✅ Sẵn sàng'; statusDiv.classList.remove('saved'); }, 2000);
      } else {
        showError(resp?.error || 'Sai tài khoản hoặc mật khẩu');
      }
    } catch (err) {
      showError('Không thể kết nối server');
    } finally {
      loginBtn.textContent = 'Đăng nhập';
      loginBtn.disabled = false;
    }
  });

  // Logout
  logoutBtn.addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ action: 'logout' });
    showLoggedOut();
    statusDiv.textContent = 'Đã đăng xuất';
  });

  function showError(msg) { loginError.textContent = msg; loginError.classList.add('show'); }
  function hideError() { loginError.classList.remove('show'); }

  // Settings
  hoverDelaySlider.addEventListener('input', () => {
    delayValue.textContent = (hoverDelaySlider.value / 1000) + 's';
  });

  function saveSettings() {
    chrome.runtime.sendMessage({
      action: 'saveSettings',
      settings: {
        enabled: enabledCheckbox.checked,
        hoverDelay: parseInt(hoverDelaySlider.value),
        showTooltip: showTooltipCheckbox.checked
      }
    }, (resp) => {
      if (resp && resp.success) {
        statusDiv.textContent = '✓ Đã lưu';
        statusDiv.classList.add('saved');
        setTimeout(() => { statusDiv.textContent = '✅ Sẵn sàng'; statusDiv.classList.remove('saved'); }, 1500);
      }
    });
  }

  enabledCheckbox.addEventListener('change', saveSettings);
  hoverDelaySlider.addEventListener('change', saveSettings);
  showTooltipCheckbox.addEventListener('change', saveSettings);
});