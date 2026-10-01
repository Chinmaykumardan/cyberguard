/**
 * HoneyShield Secure Password Generator Module
 * Generates high-entropy credentials locally using the Web Crypto API.
 */
import { showToast } from './dashboard.js';

export function generatePassword() {
  const lengthInput = document.getElementById('passwordLength');
  const output = document.getElementById('generatedPassword');
  if (!output) return;

  const length = Number(lengthInput ? lengthInput.value : 20);
  const chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*_-+=';
  const random = new Uint32Array(length);
  window.crypto.getRandomValues(random);
  output.value = Array.from(random).map(num => chars[num % chars.length]).join('');
}

export function initPasswordGenerator() {
  const genBtn = document.getElementById('generatePassword');
  const lengthSlider = document.getElementById('passwordLength');
  const lengthValue = document.getElementById('lengthValue');
  const copyBtn = document.getElementById('copyPassword');

  if (genBtn) {
    genBtn.addEventListener('click', generatePassword);
  }

  if (lengthSlider) {
    lengthSlider.addEventListener('input', event => {
      if (lengthValue) lengthValue.textContent = event.target.value;
      generatePassword();
    });
  }

  if (copyBtn) {
    copyBtn.addEventListener('click', async () => {
      const output = document.getElementById('generatedPassword');
      if (!output || !output.value) return;
      try {
        await navigator.clipboard.writeText(output.value);
        showToast('Generated password copied to clipboard.');
      } catch {
        showToast('Copy unavailable. Select the password manually.');
      }
    });
  }

  // Initial generation
  generatePassword();
}
