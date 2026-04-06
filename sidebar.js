/* ── APEX SIDEBAR.JS ─────────────────────────────────────────
   Shared across all app pages. Handles:
   - Sidebar HTML injection + active nav state
   - User identity display
   - Plan-aware UI (rings, badges, counters)
   - User menu popup
   - Auth helpers (doLogout, startCheckout)
──────────────────────────────────────────────────────────── */

(function () {

  // ── SIDEBAR HTML ─────────────────────────────────────────
  const SIDEBAR_HTML = `
<aside class="sidebar">
  <a class="sidebar-logo" href="dashboard.html">
    <div class="logo-mark">
      <svg viewBox="0 0 16 16" fill="none">
        <path d="M8 2L13 5V11L8 14L3 11V5L8 2Z" stroke="white" stroke-width="1.5" stroke-linejoin="round"/>
        <circle cx="8" cy="8" r="2" fill="white"/>
      </svg>
    </div>
    <span class="logo-name">Apex</span>
  </a>

  <nav class="sidebar-nav">
    <div class="nav-section-label">Overview</div>
    <a class="nav-item" href="dashboard.html" data-page="dashboard">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
      Dashboard
    </a>
    <a class="nav-item" href="performance.html" data-page="performance">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      Performance
    </a>

    <div class="nav-section-label" style="margin-top:10px;">Practice</div>
    <a class="nav-item" href="practice-screen.html" data-page="practice">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>
      Practice All
    </a>
    <a class="nav-item" href="saved-questions.html" data-page="saved">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21l-7-5-7 5V5a2 2 0 012-2h10a2 2 0 012 2z"/></svg>
      Saved Questions
    </a>

    <div class="nav-section-label" style="margin-top:10px;">Topics</div>
    <a class="nav-item" href="practice-screen.html?topic=Accounting">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg>
      Accounting
    </a>
    <a class="nav-item" href="practice-screen.html?topic=Enterprise_Value">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v2"/></svg>
      Enterprise Value
    </a>
    <a class="nav-item" href="practice-screen.html?topic=Valuation">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/></svg>
      Valuation
    </a>
    <a class="nav-item" href="practice-screen.html?topic=DCF">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      Discounted Cash Flow
    </a>
    <a class="nav-item" href="practice-screen.html?topic=Mergers_MA">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/></svg>
      Mergers &amp; Acquisitions
    </a>
    <a class="nav-item" href="practice-screen.html?topic=LBO">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
      Leveraged Buyouts
    </a>
  </nav>

  <div class="sidebar-bottom">
    <a href="pricing.html" class="upgrade-btn" id="upgradeBtn">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>
      Upgrade to Pro
    </a>
    <div class="user-card" id="userCard">
      <div class="user-avatar" id="sidebarAvatar">?</div>
      <div>
        <div class="user-name" id="sidebarUserName">—</div>
        <div class="user-plan" id="sidebarPlan">Free plan</div>
      </div>
    </div>
  </div>
</aside>`;

  // ── INJECT SIDEBAR ────────────────────────────────────────
  function injectSidebar() {
    const mount = document.getElementById('sidebar-mount');
    if (!mount) return;
    mount.outerHTML = SIDEBAR_HTML;

    // Mark active nav item based on current page
    const page = document.body.dataset.page;
    if (page) {
      const active = document.querySelector(`.nav-item[data-page="${page}"]`);
      if (active) active.classList.add('active');
    }
  }

  // ── PLAN UI ───────────────────────────────────────────────
  function updateSidebarPlanText(plan, gradedToday) {
    const el = document.getElementById('sidebarPlan');
    if (!el) return;
    if (plan === 'pass') {
      el.textContent = 'Recruiting Pass'; el.style.color = '#D97706';
    } else if (plan === 'monthly') {
      el.textContent = 'Monthly plan'; el.style.color = '#2563EB';
    } else if (plan === 'guest') {
      const r = Math.max(0, 5 - (gradedToday || 0));
      el.textContent = 'Free · ' + r + ' grade' + (r !== 1 ? 's' : '') + ' left today';
    } else {
      const r = Math.max(0, 5 - (gradedToday || 0));
      el.textContent = 'Free · ' + r + ' grade' + (r !== 1 ? 's' : '') + ' left today';
    }
  }

  function initSidebarMenu(plan, gradedToday) {
    const card = document.getElementById('userCard');
    if (!card) return;

    // Guests → redirect to auth on click
    if (plan === 'guest') {
      card.setAttribute('onclick', "window.location.href='auth.html?next=practice-screen.html'");
      card.title = 'Sign in or create an account';
      updateSidebarPlanText('guest', gradedToday);
      return;
    }

    card.setAttribute('onclick', 'window._sidebarToggleMenu()');

    // Avatar ring for paid users
    const avatar = document.getElementById('sidebarAvatar');
    if (avatar && (plan === 'monthly' || plan === 'pass')) {
      const wrap = document.createElement('div');
      wrap.className = 'user-avatar-wrap';
      avatar.parentNode.insertBefore(wrap, avatar);
      wrap.appendChild(avatar);
      const ring = document.createElement('div');
      ring.className = 'plan-ring ' + (plan === 'pass' ? 'plan-ring-pass' : 'plan-ring-monthly');
      wrap.appendChild(ring);
      const icon = document.createElement('div');
      icon.className = 'plan-icon ' + (plan === 'pass' ? 'plan-icon-pass' : 'plan-icon-monthly');
      icon.textContent = plan === 'pass' ? '◆' : '★';
      wrap.appendChild(icon);
    }

    updateSidebarPlanText(plan, gradedToday);

    // Hide upgrade button for paid users
    const upgradeBtn = document.getElementById('upgradeBtn');
    if (upgradeBtn && plan !== 'free') upgradeBtn.style.display = 'none';
  }

  // ── USER MENU ─────────────────────────────────────────────
  let _menuOpen = false;

  window._sidebarToggleMenu = function () {
    const existing = document.getElementById('userMenu');
    if (existing) { existing.remove(); _menuOpen = false; return; }
    _menuOpen = true;

    const plan        = window._userPlan || 'free';
    const gt          = window._gradedToday || 0;
    const name        = localStorage.getItem('apex_user') || '—';
    const email       = localStorage.getItem('apex_email') || '';
    const memberSince = window._memberSince;

    const initials = name.split(' ').map(w => w[0]).join('').slice(0,2).toUpperCase();

    let bc = 'badge-free', bt = '✦ Free plan';
    if (plan === 'monthly') { bc = 'badge-monthly'; bt = '★ Monthly'; }
    if (plan === 'pass')    { bc = 'badge-pass';    bt = '◆ Recruiting Pass'; }

    const memberLine = memberSince
      ? `<div class="menu-member-since">Member since ${new Date(memberSince * 1000).toLocaleDateString('en-US', {month:'long', year:'numeric'})}</div>`
      : '';

    const gradeRow = plan === 'free'
      ? `<div class="menu-divider"></div>
         <div class="menu-item menu-item-info">
           <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
           ${Math.max(0, 5 - gt)} of 5 free grades left today
         </div>` : '';

    const upgradeRow = plan === 'free'
      ? `<div class="menu-divider"></div>
         <a class="menu-item" href="pricing.html">
           <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>
           Upgrade to Pro
         </a>` : '';

    const menu = document.createElement('div');
    menu.id = 'userMenu';
    menu.className = 'user-menu';
    menu.innerHTML = `
      <div class="menu-header">
        <div class="menu-header-avatar">${initials}</div>
        <div class="menu-header-text">
          <div class="menu-user-name">${name}</div>
          ${email ? `<div class="menu-user-email">${email}</div>` : ''}
          <span class="menu-plan-badge ${bc}">${bt}</span>
          ${memberLine}
        </div>
      </div>
      ${gradeRow}
      ${upgradeRow}
      <div class="menu-divider"></div>
      <div class="menu-item menu-item-danger" onclick="doLogout()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        Sign out
      </div>`;

    const bottom = document.querySelector('.sidebar-bottom');
    if (bottom) { bottom.style.position = 'relative'; bottom.appendChild(menu); }

    setTimeout(() => {
      document.addEventListener('click', function close(e) {
        const card = document.getElementById('userCard');
        if (!menu.contains(e.target) && (!card || !card.contains(e.target))) {
          menu.remove(); _menuOpen = false;
          document.removeEventListener('click', close);
        }
      });
    }, 0);
  };

  // ── AUTH HELPERS ──────────────────────────────────────────
  window.doLogout = function () {
    localStorage.removeItem('apex_token');
    localStorage.removeItem('apex_user');
    window.location.href = 'auth.html';
  };

  window.startCheckout = async function (plan) {
    const token = localStorage.getItem('apex_token');
    if (!token) { window.location.href = 'pricing.html'; return; }
    try {
      const r = await fetch('/api/stripe/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify({ plan })
      });
      const data = await r.json();
      if (data.url) window.location.href = data.url;
      else alert('Could not start checkout. Please try from the pricing page.');
    } catch (e) {
      window.location.href = 'pricing.html';
    }
  };

  // ── BOOT ──────────────────────────────────────────────────
  // Inject sidebar immediately (script is loaded at bottom of body)
  injectSidebar();

  // Expose helpers globally for pages to call
  window.initSidebarMenu      = initSidebarMenu;
  window.updateSidebarPlanText = updateSidebarPlanText;

})();
