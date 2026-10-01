/**
 * HoneyShield HTTP Security Headers Analyzer Module
 * Inspects response header text and safely builds report items using DOM APIs.
 */

export function initHeadersAnalyzer() {
  const analyzeBtn = document.getElementById('analyzeHeaders');
  const input = document.getElementById('headersInput');
  const scoreEl = document.getElementById('headerScore');
  const verdictEl = document.getElementById('headerVerdict');
  const detailEl = document.getElementById('headerDetail');
  const resultsContainer = document.getElementById('headerResults');

  if (!analyzeBtn || !input) return;

  analyzeBtn.addEventListener('click', () => {
    const text = (input.value || '').toLowerCase();
    const checks = [
      ['Content-Security-Policy', text.includes('content-security-policy')],
      ['Strict-Transport-Security', text.includes('strict-transport-security')],
      ['Clickjacking protection', text.includes('x-frame-options') || text.includes('frame-ancestors')],
      ['MIME sniffing defense', text.includes('x-content-type-options')]
    ];

    const passedCount = checks.filter(([, ok]) => ok).length;
    const score = passedCount * 25;

    if (scoreEl) scoreEl.textContent = String(score);
    if (verdictEl) {
      verdictEl.textContent = score >= 75 ? 'Good baseline coverage' : score ? 'Headers need improvement' : 'No protections detected';
    }
    if (detailEl) {
      detailEl.textContent = `${passedCount} of ${checks.length} recommended checks found`;
    }

    if (resultsContainer) {
      // Clear safely using DOM manipulation (no innerHTML)
      while (resultsContainer.firstChild) {
        resultsContainer.removeChild(resultsContainer.firstChild);
      }

      // Build safe DOM nodes
      checks.forEach(([name, ok]) => {
        const li = document.createElement('li');
        const spanName = document.createElement('span');
        spanName.textContent = name;

        const spanStatus = document.createElement('span');
        spanStatus.textContent = ok ? 'Present' : 'Missing';
        if (!ok) {
          spanStatus.className = 'warn';
        }

        li.appendChild(spanName);
        li.appendChild(spanStatus);
        resultsContainer.appendChild(li);
      });
    }
  });
}
