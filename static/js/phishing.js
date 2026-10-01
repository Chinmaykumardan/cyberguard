/**
 * HoneyShield Phishing & Social Engineering Analyzer Module
 * Analyzes communication content for deceit cues and builds evidence lists safely.
 */

export function initPhishingAnalyzer() {
  const analyzeBtn = document.getElementById('analyzePhish');
  const input = document.getElementById('phishingInput');
  const scoreRing = document.getElementById('phishScore');
  const verdictEl = document.getElementById('phishVerdict');
  const detailEl = document.getElementById('phishDetail');
  const resultsContainer = document.getElementById('phishResults');

  if (!analyzeBtn || !input) return;

  analyzeBtn.addEventListener('click', () => {
    const text = (input.value || '').toLowerCase();
    const indicators = [
      ['Urgency language', /(urgent|immediately|suspend|within 24|act now)/.test(text)],
      ['Link indicators', /(https?:\/\/|www\.)/.test(text)],
      ['Credential request', /(password|sign in|login|verify your account|credentials)/.test(text)],
      ['Payment pressure', /(payment|invoice|bank|gift card|crypto)/.test(text)]
    ];

    const detectedCount = indicators.filter(([, yes]) => yes).length;
    const risk = Math.min(100, detectedCount * 25);

    if (scoreRing) {
      scoreRing.textContent = String(risk);
      scoreRing.className = `verdict-ring ${risk >= 50 ? 'ring-red' : risk ? 'ring-amber' : 'ring-green'}`;
    }

    if (verdictEl) {
      verdictEl.textContent = risk >= 75 ? 'Likely phishing' : risk >= 25 ? 'Review with caution' : 'Low-risk content';
    }

    if (detailEl) {
      detailEl.textContent = `${detectedCount} signal(s) found in local analysis`;
    }

    if (resultsContainer) {
      // Safe DOM construction (no innerHTML)
      while (resultsContainer.firstChild) {
        resultsContainer.removeChild(resultsContainer.firstChild);
      }

      indicators.forEach(([name, yes]) => {
        const li = document.createElement('li');
        const spanName = document.createElement('span');
        spanName.textContent = name;

        const spanStatus = document.createElement('span');
        spanStatus.textContent = yes ? 'Detected' : 'Not detected';
        if (yes) {
          spanStatus.className = 'warn';
        }

        li.appendChild(spanName);
        li.appendChild(spanStatus);
        resultsContainer.appendChild(li);
      });
    }
  });
}
