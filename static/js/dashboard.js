/**
 * HoneyShield Dashboard Module
 * Manages canvas visualization, tab navigation, and live telemetry rendering.
 */

export function showToast(message) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(window.toastTimer);
  window.toastTimer = setTimeout(() => toast.classList.remove('show'), 2700);
}

export function drawLineChart(canvas, data, options = {}) {
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const width = Math.max(280, rect.width || 500);
  const height = Math.max(120, rect.height || 230);
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);
  const pad = { top: 14, right: 10, bottom: 27, left: 30 };
  const max = Math.max(...data, 10) * 1.18;
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  ctx.strokeStyle = 'rgba(139,182,171,.13)';
  ctx.lineWidth = 1;
  for (let i = 0; i < 4; i++) {
    const y = pad.top + (plotH / 3) * i;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(width - pad.right, y);
    ctx.stroke();
    ctx.fillStyle = '#668078';
    ctx.font = '10px monospace';
    ctx.fillText(String(Math.round(max - (max / 3) * i)), 1, y + 3);
  }

  const points = data.map((value, index) => ({
    x: pad.left + (index / (Math.max(1, data.length - 1))) * plotW,
    y: pad.top + plotH - (value / max) * plotH
  }));

  const gradient = ctx.createLinearGradient(0, pad.top, 0, height - pad.bottom);
  gradient.addColorStop(0, options.fill || 'rgba(98,237,185,.28)');
  gradient.addColorStop(1, 'rgba(98,237,185,0)');
  ctx.beginPath();
  points.forEach((point, index) => index ? ctx.lineTo(point.x, point.y) : ctx.moveTo(point.x, point.y));
  ctx.lineTo(points[points.length - 1].x, height - pad.bottom);
  ctx.lineTo(points[0].x, height - pad.bottom);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();

  ctx.beginPath();
  points.forEach((point, index) => index ? ctx.lineTo(point.x, point.y) : ctx.moveTo(point.x, point.y));
  ctx.strokeStyle = options.stroke || '#62edb9';
  ctx.lineWidth = 2;
  ctx.stroke();

  if (points.length > 0) {
    const last = points[points.length - 1];
    ctx.fillStyle = options.stroke || '#62edb9';
    ctx.beginPath();
    ctx.arc(last.x, last.y, 3.7, 0, Math.PI * 2);
    ctx.fill();
  }

  ctx.fillStyle = '#729088';
  ctx.font = '10px monospace';
  ['60m', '45m', '30m', '15m', 'Now'].forEach((label, i) => {
    ctx.fillText(label, pad.left + (plotW / 4) * i - 8, height - 7);
  });
}

export function initDashboard() {
  const pages = Array.from(document.querySelectorAll('.page'));
  const navLinks = Array.from(document.querySelectorAll('.nav-link'));
  const crumb = document.getElementById('crumb');
  let activeIp = null;

  function navigate(pageId) {
    pages.forEach(page => page.classList.toggle('active', page.id === pageId));
    navLinks.forEach(link => link.classList.toggle('active', link.dataset.page === pageId));
    const selected = navLinks.find(link => link.dataset.page === pageId);
    if (crumb) {
      crumb.textContent = selected ? selected.textContent.trim().toUpperCase() : pageId.toUpperCase();
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  navLinks.forEach(link => {
    link.addEventListener('click', () => navigate(link.dataset.page));
  });

  document.querySelectorAll('[data-page]').forEach(button => {
    if (!button.classList.contains('nav-link')) {
      button.addEventListener('click', () => navigate(button.dataset.page));
    }
  });

  const refreshBtn = document.getElementById('refreshButton');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      const count = document.getElementById('attemptCount');
      if (count) {
        count.textContent = (1284 + Math.floor(Math.random() * 17)).toLocaleString();
      }
      const refreshTime = document.getElementById('refreshTime');
      if (refreshTime) {
        refreshTime.textContent = 'just now';
      }
      drawCharts();
      showToast('Dashboard refreshed with live telemetry.');
    });
  }

  function drawCharts() {
    const chart = document.getElementById('attemptChart');
    if (chart) {
      drawLineChart(chart, [12, 18, 16, 25, 22, 29, 24, 32, 28, 41, 34, 38, 48, 45, 58, 51, 62, 56, 67, 71, 62, 78, 73, 82, 76, 88, 79, 94]);
    }
  }

  // Initial draw
  drawCharts();
  window.addEventListener('resize', drawCharts);

  // Unblock Dialog Handling
  const dialog = document.getElementById('confirmDialog');
  const dialogText = document.getElementById('dialogText');
  const cancelBtn = document.getElementById('cancelUnblock');
  const confirmBtn = document.getElementById('confirmUnblock');

  document.querySelectorAll('#blockedTable .unblock').forEach(button => {
    button.addEventListener('click', () => {
      activeIp = button.dataset.ip;
      if (dialogText) {
        dialogText.textContent = `${activeIp} will be allowed to reach protected login routes again. Existing event history will be retained.`;
      }
      if (dialog && typeof dialog.showModal === 'function') {
        dialog.showModal();
      }
    });
  });

  if (cancelBtn && dialog) {
    cancelBtn.addEventListener('click', () => dialog.close());
  }

  if (confirmBtn && dialog) {
    confirmBtn.addEventListener('click', () => {
      const rows = Array.from(document.querySelectorAll('#blockedTable tr'));
      const targetRow = rows.find(item => item.textContent.includes(activeIp));
      if (targetRow) targetRow.remove();
      dialog.close();
      showToast(`${activeIp} has been removed from the block list.`);
    });
  }

  const mobileMenu = document.getElementById('mobileMenu');
  if (mobileMenu) {
    mobileMenu.addEventListener('click', () => {
      showToast('Use the desktop console for full navigation.');
    });
  }
}
