/**
 * HoneyShield Password Strength Analyzer Module
 * Local-only entropy calculations and offline crack time estimations.
 */
import { drawLineChart } from './dashboard.js';

export function calculatePassword(password) {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/\d/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 32;
  let entropy = password.length * Math.log2(pool || 1);
  const common = ['password', 'qwerty', 'letmein', 'welcome', 'admin', '123456', 'iloveyou'];
  const patterned = /(.)\1{2,}|1234|abcd|qwerty|password/i.test(password) || common.some(word => password.toLowerCase().includes(word));
  if (patterned) entropy *= 0.52;
  return { entropy: Math.round(entropy), patterned };
}

export function drawEntropyChart() {
  const input = document.getElementById('strengthPassword');
  const chart = document.getElementById('entropyChart');
  if (!input || !chart) return;
  const value = input.value || '';
  const data = value.length ? [...value].map((_, i) => calculatePassword(value.slice(0, i + 1)).entropy) : [0, 0];
  drawLineChart(chart, data, { stroke: '#5bdbf7', fill: 'rgba(91,219,247,.22)' });
}

export function initPasswordStrength() {
  const input = document.getElementById('strengthPassword');
  const fill = document.getElementById('strengthFill');
  const scoreEl = document.getElementById('strengthScore');
  const labelEl = document.getElementById('strengthLabel');
  const entropyText = document.getElementById('entropyText');
  const crackTime = document.getElementById('crackTime');

  if (!input) return;

  input.addEventListener('input', event => {
    const password = event.target.value;
    const { entropy, patterned } = calculatePassword(password);
    let score = Math.min(100, Math.round(entropy * 1.05));
    const levels = [
      { max: 24, label: 'Very weak', color: '#ff6b77' },
      { max: 40, label: 'Weak', color: '#ff9364' },
      { max: 58, label: 'Fair', color: '#ffbd5b' },
      { max: 76, label: 'Strong', color: '#83d98b' },
      { max: 101, label: 'Excellent', color: '#62edb9' }
    ];
    const level = levels.find(item => score < item.max) || levels[levels.length - 1];

    if (fill) {
      fill.style.width = `${Math.max(4, score)}%`;
      fill.style.background = level.color;
    }
    if (scoreEl) {
      scoreEl.style.color = level.color;
      scoreEl.textContent = String(score);
    }
    if (labelEl) {
      labelEl.textContent = level.label;
    }
    if (entropyText) {
      entropyText.textContent = `${entropy} bits estimated entropy · ${password.length} characters`;
    }

    const seconds = Math.pow(2, entropy) / 1e10;
    if (crackTime) {
      crackTime.textContent = seconds < 1 ? 'Instantly' : seconds < 3600 ? `${Math.round(seconds / 60)} minutes` : seconds < 31536000 ? `${Math.round(seconds / 86400)} days` : `${Math.round(seconds / 31536000).toLocaleString()} years`;
    }

    const checks = {
      tipLength: password.length >= 14,
      tipUpper: /[A-Z]/.test(password),
      tipNumber: /\d/.test(password),
      tipSymbol: /[^A-Za-z0-9]/.test(password),
      tipPattern: password.length > 0 && !patterned
    };

    Object.entries(checks).forEach(([id, ok]) => {
      const el = document.getElementById(id);
      if (el) el.classList.toggle('ok', ok);
    });

    drawEntropyChart();
  });

  drawEntropyChart();
}
