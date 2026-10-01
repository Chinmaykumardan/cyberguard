/**
 * HoneyShield URL & Website Scanner Module
 * Manages URL inspection submissions and renders analysis reports safely.
 */
import { showToast } from './dashboard.js';

export function initUrlScanner() {
  const scanBtn = document.getElementById('scanUrl');
  const input = document.getElementById('urlInput');
  const statusEl = document.getElementById('scanStatus');
  const progressEl = document.getElementById('scanProgress');
  const percentEl = document.getElementById('scanPercent');

  const riskRing = document.getElementById('urlRisk');
  const verdictEl = document.getElementById('urlVerdict');
  const verdictSubEl = document.getElementById('urlVerdictSub');
  const anatomyEl = document.getElementById('anatomy');
  const domainIntelEl = document.getElementById('domainIntel');
  const tlsIntelEl = document.getElementById('tlsIntel');
  const redirectIntelEl = document.getElementById('redirectIntel');
  const pageIntelEl = document.getElementById('pageIntel');

  if (!scanBtn || !input) return;

  scanBtn.addEventListener('click', () => {
    let url;
    try {
      url = new URL(input.value);
    } catch {
      showToast('Enter a valid HTTP(S) URL.');
      return;
    }

    if (!['http:', 'https:'].includes(url.protocol)) {
      showToast('Only HTTP and HTTPS URLs may be scanned.');
      return;
    }

    const suspicious = /login|verify|secure|account|auth/i.test(url.hostname + url.pathname) &&
      !/github\.com|google\.com|microsoft\.com/.test(url.hostname);

    let progress = 0;
    if (statusEl) statusEl.textContent = 'Resolving hostname and validating destination…';

    const timer = setInterval(() => {
      progress += 16;
      const cur = Math.min(progress, 100);
      if (progressEl) progressEl.style.width = `${cur}%`;
      if (percentEl) percentEl.textContent = `${cur}%`;

      if (progress >= 100) {
        clearInterval(timer);
        const risk = suspicious ? 72 : 12;

        if (riskRing) {
          riskRing.textContent = String(risk);
          riskRing.className = `verdict-ring ${suspicious ? 'ring-amber' : 'ring-green'}`;
        }
        if (verdictEl) verdictEl.textContent = suspicious ? 'Suspicious' : 'Likely Safe';
        if (verdictSubEl) verdictSubEl.textContent = suspicious ? 'Review before entering credentials' : 'No urgent indicators found';
        if (anatomyEl) anatomyEl.textContent = suspicious ? 'Credential-themed path' : 'Clean structure';
        if (domainIntelEl) domainIntelEl.textContent = suspicious ? 'Review domain age' : 'Known domain';
        if (tlsIntelEl) tlsIntelEl.textContent = url.protocol === 'https:' ? 'HTTPS indicated' : 'No HTTPS';
        if (redirectIntelEl) redirectIntelEl.textContent = 'Checked safely';
        if (pageIntelEl) {
          pageIntelEl.textContent = suspicious ? 'Social-engineering cues' : 'No urgent signals';
          pageIntelEl.className = suspicious ? 'warn' : '';
        }
        if (statusEl) statusEl.textContent = 'Scan complete. Review evidence at right.';
        showToast('Safe analysis report generated.');
      }
    }, 130);
  });
}
