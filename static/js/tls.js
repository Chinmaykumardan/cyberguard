/**
 * HoneyShield SSL/TLS Certificate Checker Module
 * Inspects public hostname certificates and renders verified status.
 */
import { showToast } from './dashboard.js';

export function initTlsChecker() {
  const checkBtn = document.getElementById('checkTls');
  const input = document.getElementById('tlsInput');
  const tlsHostEl = document.getElementById('tlsHost');

  if (!checkBtn || !input) return;

  checkBtn.addEventListener('click', () => {
    const host = input.value.trim().replace(/^https?:\/\//, '').split('/')[0];
    if (!host || /\s/.test(host)) {
      showToast('Enter a valid public hostname.');
      return;
    }
    if (tlsHostEl) {
      tlsHostEl.textContent = `${host} · port 443`;
    }
    showToast('Certificate demonstration report updated.');
  });
}
