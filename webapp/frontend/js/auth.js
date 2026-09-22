/**
 * auth.js — Login / Register page logic
 * Security: honeypot detection, password strength, form validation
 */

document.addEventListener('DOMContentLoaded', () => {
  const { Auth, Toast, ApiError } = window.OSINT;

  // ── Tab switching ───────────────────────────────────────────────────────────
  const tabs = document.querySelectorAll('.auth-tab');
  const loginForm  = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');

  function switchTab(tab) {
    tabs.forEach(t => t.classList.toggle('active', t === tab));
    const target = tab.dataset.tab;
    if (loginForm)    loginForm.classList.toggle('hidden', target !== 'login');
    if (registerForm) registerForm.classList.toggle('hidden', target !== 'register');
    clearErrors();
  }

  tabs.forEach(tab => tab.addEventListener('click', () => switchTab(tab)));

  // Check URL param for initial tab
  const params = new URLSearchParams(window.location.search);
  if (params.get('tab') === 'register') {
    const regTab = document.querySelector('[data-tab="register"]');
    if (regTab) switchTab(regTab);
  }

  // ── Error display ────────────────────────────────────────────────────────────
  function showError(formId, message) {
    const banner = document.getElementById(`${formId}-error`);
    if (!banner) return;
    banner.classList.remove('hidden');
    // Safe — textContent only
    const msgEl = banner.querySelector('.error-text');
    if (msgEl) msgEl.textContent = message;
  }

  function clearErrors() {
    document.querySelectorAll('.auth-error-banner').forEach(b => b.classList.add('hidden'));
    document.querySelectorAll('.form-input').forEach(i => {
      i.classList.remove('is-error', 'is-success');
    });
  }

  function setInputState(input, state) {
    input.classList.remove('is-error', 'is-success');
    if (state) input.classList.add(state === 'ok' ? 'is-success' : 'is-error');
  }

  // ── Password strength ─────────────────────────────────────────────────────
  const pwInput = document.getElementById('register-password');
  const strengthFill = document.getElementById('strength-fill');
  const strengthLabel = document.getElementById('strength-label');

  if (pwInput) {
    pwInput.addEventListener('input', () => {
      const val = pwInput.value;
      const strength = calcPasswordStrength(val);
      if (strengthFill) {
        strengthFill.className = `password-strength-fill strength-${strength.score}`;
      }
      if (strengthLabel) {
        strengthLabel.textContent = strength.label;
        strengthLabel.style.color = strength.color;
      }
    });
  }

  function calcPasswordStrength(pw) {
    let score = 0;
    if (pw.length >= 8)  score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    score = Math.min(score, 4);
    const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
    const colors = ['', '#ef4444', '#f59e0b', '#00d4ff', '#10b981'];
    return { score, label: labels[score], color: colors[score] };
  }

  // ── Honeypot validation ────────────────────────────────────────────────────
  function isBot(formEl) {
    const hp = formEl.querySelector('.auth-honeypot input');
    return hp && hp.value !== '';
  }

  // ── Set button loading state ───────────────────────────────────────────────
  function setLoading(btn, loading) {
    if (loading) {
      btn.disabled = true;
      btn.classList.add('loading');
      btn.dataset.originalText = btn.querySelector('.btn-text')?.textContent;
    } else {
      btn.disabled = false;
      btn.classList.remove('loading');
    }
  }

  // ── Login Form ─────────────────────────────────────────────────────────────
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearErrors();

      if (isBot(loginForm)) {
        // Silently fail for bots
        return;
      }

      const emailInput = document.getElementById('login-email');
      const passwordInput = document.getElementById('login-password');
      const submitBtn = loginForm.querySelector('button[type="submit"]');

      const email = emailInput.value.trim();
      const password = passwordInput.value;

      // Client-side validation
      let hasError = false;
      if (!email || !email.includes('@')) {
        setInputState(emailInput, 'error');
        hasError = true;
      }
      if (!password) {
        setInputState(passwordInput, 'error');
        hasError = true;
      }
      if (hasError) {
        showError('login', 'Please fill in all fields correctly');
        return;
      }

      setLoading(submitBtn, true);
      try {
        await Auth.login(email, password);
        Toast.success('Logged in! Redirecting...');
        setTimeout(() => { window.location.href = '/dashboard'; }, 600);
      } catch (err) {
        const msg = err instanceof ApiError
          ? (err.status === 423 ? err.data?.error : 'Invalid email or password')
          : 'Login failed. Please try again.';
        showError('login', msg);
        setInputState(emailInput, 'error');
        setInputState(passwordInput, 'error');
      } finally {
        setLoading(submitBtn, false);
      }
    });
  }

  // ── Register Form ──────────────────────────────────────────────────────────
  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearErrors();

      if (isBot(registerForm)) return;

      const emailInput    = document.getElementById('register-email');
      const passwordInput = document.getElementById('register-password');
      const confirmInput  = document.getElementById('register-confirm');
      const submitBtn     = registerForm.querySelector('button[type="submit"]');

      const email    = emailInput.value.trim();
      const password = passwordInput.value;
      const confirm  = confirmInput?.value;

      let hasError = false;
      if (!email || !email.includes('@')) {
        setInputState(emailInput, 'error');
        hasError = true;
      }
      if (password.length < 8) {
        setInputState(passwordInput, 'error');
        hasError = true;
      }
      if (confirm !== undefined && password !== confirm) {
        setInputState(confirmInput, 'error');
        showError('register', 'Passwords do not match');
        return;
      }
      if (hasError) {
        showError('register', 'Please fix the errors above');
        return;
      }

      const strength = calcPasswordStrength(password);
      if (strength.score < 2) {
        showError('register', 'Password is too weak. Add uppercase letters, numbers, or symbols.');
        setInputState(passwordInput, 'error');
        return;
      }

      setLoading(submitBtn, true);
      try {
        await Auth.register(email, password);
        Toast.success('Account created! Welcome aboard 🎉');
        setTimeout(() => { window.location.href = '/dashboard'; }, 800);
      } catch (err) {
        const msg = err instanceof ApiError
          ? (err.data?.error || 'Registration failed')
          : 'Registration failed. Please try again.';
        showError('register', msg);
      } finally {
        setLoading(submitBtn, false);
      }
    });
  }

  // ── Redirect if already logged in ────────────────────────────────────────
  (async () => {
    try {
      await Auth.me();
      window.location.href = '/dashboard';
    } catch {
      // Not logged in — stay on page
    }
  })();
});
