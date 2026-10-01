/**
 * HoneyShield Main Application Controller
 * Boots ES modules and binds telemetry listeners.
 */
import { initDashboard } from './dashboard.js';
import { initPasswordStrength } from './password-strength.js';
import { initPasswordGenerator } from './generator.js';
import { initUrlScanner } from './url-scanner.js';
import { initHeadersAnalyzer } from './headers.js';
import { initTlsChecker } from './tls.js';
import { initPhishingAnalyzer } from './phishing.js';

document.addEventListener('DOMContentLoaded', () => {
  initDashboard();
  initPasswordStrength();
  initPasswordGenerator();
  initUrlScanner();
  initHeadersAnalyzer();
  initTlsChecker();
  initPhishingAnalyzer();
});
