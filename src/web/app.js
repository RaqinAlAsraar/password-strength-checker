// =============================================================================
// CodeNova Password Security & Entropy Auditor - Client Application
// =============================================================================

let isPasswordVisible = false;
let currentGenMode = 'random';
let debounceTimer = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('password-input');
  input.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => auditPassword(input.value), 60);
  });

  // Initial empty state audit
  auditPassword('');
  // Generate an initial credential in Generator tab
  generateCredential();
});

// Switch active tab
function switchTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));

  const targetContent = document.getElementById(`tab-${tabId}`);
  const targetBtn = document.getElementById(`tab-${tabId}-btn`);

  if (targetContent && targetBtn) {
    targetContent.classList.add('active');
    targetBtn.classList.add('active');
  }
}

// Toggle password show/hide
function toggleVisibility() {
  const input = document.getElementById('password-input');
  const eyeIcon = document.getElementById('eye-icon');
  isPasswordVisible = !isPasswordVisible;

  if (isPasswordVisible) {
    input.type = 'text';
    eyeIcon.innerHTML = `
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
      <line x1="1" y1="1" x2="23" y2="23"></line>
    `;
  } else {
    input.type = 'password';
    eyeIcon.innerHTML = `
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
      <circle cx="12" cy="12" r="3"></circle>
    `;
  }
}

function clearInput() {
  const input = document.getElementById('password-input');
  input.value = '';
  auditPassword('');
  input.focus();
}

function copyPassword() {
  const input = document.getElementById('password-input');
  if (input.value) {
    navigator.clipboard.writeText(input.value);
    showTemporaryTooltip('Password copied to clipboard!');
  }
}

// Audit credential via local in-memory API
async function auditPassword(password) {
  try {
    const res = await fetch('/api/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    const data = await res.json();
    renderAuditReport(data);
  } catch (err) {
    console.error('Audit evaluation error:', err);
  }
}

function renderAuditReport(data) {
  const tierBadge = document.getElementById('tier-badge');
  const progressFill = document.getElementById('progress-fill');
  const crackBanner = document.getElementById('crack-banner');
  const fastCrack = document.getElementById('fast-crack-time');

  if (data.password_length === 0) {
    tierBadge.textContent = 'WAITING FOR INPUT';
    tierBadge.style.backgroundColor = 'rgba(255, 255, 255, 0.05)';
    tierBadge.style.color = '#94a3b8';
    progressFill.style.width = '0%';
    progressFill.style.backgroundColor = '#64748b';
    fastCrack.textContent = 'Instant (< 1 ms)';
  } else {
    tierBadge.textContent = `${data.tier.toUpperCase()} (${data.score}/100)`;
    tierBadge.style.backgroundColor = `${data.tier_color}22`;
    tierBadge.style.color = data.tier_color;
    tierBadge.style.border = `1px solid ${data.tier_color}66`;

    progressFill.style.width = `${data.score}%`;
    progressFill.style.backgroundColor = data.tier_color;

    fastCrack.textContent = data.crack_times.fast_gpu;
    fastCrack.style.color = data.tier_color;
  }

  // Update variety chips
  const v = data.variety;
  updateChip('chip-len', 'val-len', data.password_length, data.password_length >= 14);
  updateChip('chip-upper', 'val-upper', v.upper_count, v.has_upper);
  updateChip('chip-lower', 'val-lower', v.lower_count, v.has_lower);
  updateChip('chip-digits', 'val-digits', v.digit_count, v.has_digits);
  updateChip('chip-symbols', 'val-symbols', v.symbol_count, v.has_symbols);

  // Update threats & vulnerabilities
  const threatsContainer = document.getElementById('threats-container');
  threatsContainer.innerHTML = '';

  if (data.password_length === 0) {
    threatsContainer.innerHTML = '<div class="empty-state">Enter a password above to audit security findings.</div>';
  } else {
    let hasAlerts = false;

    // Dictionary matches
    data.dictionary_findings.forEach(df => {
      hasAlerts = true;
      const item = document.createElement('div');
      item.className = 'threat-item critical';
      item.innerHTML = `<strong>🚨 Critical Dictionary Match:</strong> ${escapeHtml(df.description)}`;
      threatsContainer.appendChild(item);
    });

    // Pattern & sequence findings
    data.pattern_findings.forEach(pf => {
      hasAlerts = true;
      const isHigh = pf.severity === 'high';
      const item = document.createElement('div');
      item.className = `threat-item ${isHigh ? 'critical' : 'warning'}`;
      item.innerHTML = `<strong>⚡ ${escapeHtml(pf.description)}</strong> [Snippet: <code>${escapeHtml(pf.match_snippet)}</code>]`;
      threatsContainer.appendChild(item);
    });

    if (!hasAlerts) {
      const item = document.createElement('div');
      item.className = 'threat-item success';
      item.innerHTML = '<strong>✓ Clean Credential:</strong> No leaked dictionary words, keyboard walks, or predictable sequences detected.';
      threatsContainer.appendChild(item);
    }
  }

  // Update suggestions
  const suggContainer = document.getElementById('suggestions-container');
  suggContainer.innerHTML = '';

  if (data.password_length === 0) {
    suggContainer.innerHTML = '<li class="suggestion-item">Enter a credential to view specific recommendations.</li>';
  } else if (data.suggestions.length === 0) {
    suggContainer.innerHTML = '<li class="suggestion-item" style="color: #34d399; font-weight: 600;">✓ Excellent password! Credential satisfies all strict entropy criteria.</li>';
  } else {
    data.suggestions.forEach(s => {
      const li = document.createElement('li');
      li.className = 'suggestion-item';
      li.textContent = `• ${s}`;
      suggContainer.appendChild(li);
    });
  }

  // Update technical math accordion
  document.getElementById('shannon-val').textContent = `${data.shannon_entropy.total_bits.toFixed(2)} bits`;
  document.getElementById('shannon-rate').textContent = `${data.shannon_entropy.bits_per_char.toFixed(2)} bits / char`;
  document.getElementById('keyspace-val').textContent = `${data.keyspace_entropy.entropy_bits.toFixed(2)} bits`;
  document.getElementById('keyspace-pool').textContent = `Pool size: ${data.keyspace_entropy.pool_size} chars (${data.keyspace_entropy.unique_chars} unique)`;
  document.getElementById('slow-crack-time').textContent = data.crack_times.slow_argon2;
  document.getElementById('online-crack-time').textContent = data.crack_times.online;
}

function updateChip(chipId, valId, count, isValid) {
  const chip = document.getElementById(chipId);
  const val = document.getElementById(valId);
  const icon = chip.querySelector('.chip-icon');

  val.textContent = count;
  if (isValid) {
    chip.classList.add('valid');
    icon.textContent = '✓';
  } else {
    chip.classList.remove('valid');
    icon.textContent = '✗';
  }
}

// Generator Controls
function onGenModeChange() {
  const mode = document.querySelector('input[name="gen-mode"]:checked').value;
  currentGenMode = mode;
  const slider = document.getElementById('length-slider');
  const sliderLabel = document.getElementById('slider-label');
  const bubble = document.getElementById('slider-val-bubble');
  const randomOpts = document.getElementById('random-options');
  const ppOpts = document.getElementById('passphrase-options');

  if (mode === 'passphrase') {
    sliderLabel.textContent = 'Word Count:';
    slider.min = 3;
    slider.max = 8;
    slider.value = 5;
    bubble.textContent = '5';
    randomOpts.classList.add('hidden');
    ppOpts.classList.remove('hidden');
  } else {
    sliderLabel.textContent = 'Password Length:';
    slider.min = 8;
    slider.max = 40;
    slider.value = 18;
    bubble.textContent = '18';
    randomOpts.classList.remove('hidden');
    ppOpts.classList.add('hidden');
  }

  generateCredential();
}

function onSliderInput(val) {
  document.getElementById('slider-val-bubble').textContent = val;
  generateCredential();
}

async function generateCredential() {
  const sliderVal = parseInt(document.getElementById('length-slider').value, 10);
  let payload = {};

  if (currentGenMode === 'passphrase') {
    payload = {
      mode: 'passphrase',
      words: sliderVal,
      separator: '-',
      capitalize: document.getElementById('chk-pp-cap').checked,
      append_number: document.getElementById('chk-pp-num').checked,
    };
  } else {
    payload = {
      mode: 'random',
      length: sliderVal,
      upper: document.getElementById('chk-upper').checked,
      lower: document.getElementById('chk-lower').checked,
      digits: document.getElementById('chk-digits').checked,
      symbols: document.getElementById('chk-symbols').checked,
    };
  }

  try {
    const res = await fetch('/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    document.getElementById('generated-pwd-text').textContent = data.password;
  } catch (err) {
    console.error('Generate error:', err);
  }
}

function copyGenerated() {
  const pwd = document.getElementById('generated-pwd-text').textContent;
  if (pwd) {
    navigator.clipboard.writeText(pwd);
    showTemporaryTooltip('Generated credential copied to clipboard!');
  }
}

function useInAuditor() {
  const pwd = document.getElementById('generated-pwd-text').textContent;
  if (pwd) {
    const input = document.getElementById('password-input');
    input.value = pwd;
    switchTab('auditor');
    auditPassword(pwd);
  }
}

function showTemporaryTooltip(msg) {
  const tip = document.createElement('div');
  tip.textContent = msg;
  tip.style.position = 'fixed';
  tip.style.bottom = '24px';
  tip.style.left = '50%';
  tip.style.transform = 'translateX(-50%)';
  tip.style.backgroundColor = '#06b6d4';
  tip.style.color = '#000';
  tip.style.fontWeight = '700';
  tip.style.padding = '10px 20px';
  tip.style.borderRadius = '9999px';
  tip.style.boxShadow = '0 4px 14px rgba(0,0,0,0.4)';
  tip.style.zIndex = '9999';
  document.body.appendChild(tip);
  setTimeout(() => tip.remove(), 1800);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
