/**
 * HoneyShield Login Behavioral Telemetry
 * Captures typing velocity, pointer dynamics, and submission latency
 * for AI risk classification and bot detection without capturing plaintext data.
 */
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('loginForm');
  if (!form) return;

  const pageLoadTime = performance.now();
  let mouseMoveCount = 0;
  let keyStrokeCount = 0;
  let typingStartTime = null;
  let pasteDetected = false;

  // Track mouse and touch movements
  window.addEventListener('mousemove', () => {
    mouseMoveCount++;
  }, { passive: true });

  window.addEventListener('touchmove', () => {
    mouseMoveCount++;
  }, { passive: true });

  // Track typing telemetry on inputs
  const inputs = form.querySelectorAll('input:not([type="hidden"])');
  inputs.forEach(input => {
    input.addEventListener('keydown', () => {
      if (!typingStartTime) {
        typingStartTime = performance.now();
      }
      keyStrokeCount++;
    });

    input.addEventListener('paste', () => {
      pasteDetected = true;
    });
  });

  // Intercept form submission or formdata event to append telemetry
  form.addEventListener('formdata', event => {
    const elapsedSeconds = typingStartTime ? (performance.now() - typingStartTime) / 1000 : 0.1;
    const wordsEstimate = (keyStrokeCount / 5);
    const typingSpeedWpm = elapsedSeconds > 0 ? Math.round((wordsEstimate / (elapsedSeconds / 60))) : 0;
    const timeToSubmitMs = Math.round(performance.now() - pageLoadTime);

    event.formData.set('mouse_moves', String(mouseMoveCount));
    event.formData.set('typing_speed_wpm', String(typingSpeedWpm));
    event.formData.set('paste_detected', pasteDetected ? '1' : '0');
    event.formData.set('time_to_submit_ms', String(timeToSubmitMs));
  });
});
