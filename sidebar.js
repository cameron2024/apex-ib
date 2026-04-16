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

    // Mark active nav item based on current page + URL
    const page = document.body.dataset.page;
    const currentHref = window.location.pathname + window.location.search;

    // First try exact URL match (handles topic links like ?topic=Accounting)
    let matched = false;
    document.querySelectorAll('.nav-item').forEach(item => {
      const itemPath = item.getAttribute('href') || '';
      // Normalize: strip leading slash differences, compare pathname+search
      const a = document.createElement('a');
      a.href = itemPath;
      const itemFull = a.pathname + a.search;
      if (itemFull === currentHref) {
        item.classList.add('active');
        matched = true;
      }
    });

    // Fallback: match by data-page (for pages without query params)
    if (!matched && page) {
      const active = document.querySelector(`.nav-item[data-page="${page}"]`);
      if (active) active.classList.add('active');
    }

    // Apply saved avatar immediately
    applyAvatarToSidebar();
  }

  // ── AVATAR HELPERS ────────────────────────────────────────
  function applyAvatarToSidebar() {
    const url = localStorage.getItem('apex_avatar');
    const el = document.getElementById('sidebarAvatar');
    if (!el) return;
    const existing = el.querySelector('img.sidebar-av-photo');
    if (url) {
      if (!existing) {
        const img = document.createElement('img');
        img.className = 'sidebar-av-photo';
        img.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;border-radius:50%;object-fit:cover;z-index:1;';
        el.appendChild(img);
        img.src = url;
      } else {
        existing.src = url;
      }
      el.style.backgroundImage = '';
      el.style.position = 'relative';
    } else {
      if (existing) existing.remove();
      el.style.backgroundImage = '';
    }
  }

  function applyAvatarToMenu() {
    const url = localStorage.getItem('apex_avatar');
    const menuAv = document.getElementById('menuHeaderAvatar');
    if (!menuAv) return;
    const existing = menuAv.querySelector('img.av-photo');
    if (url && !existing) {
      const img = document.createElement('img');
      img.className = 'av-photo';
      img.src = url;
      menuAv.insertBefore(img, menuAv.firstChild);
      menuAv.querySelector('.av-initials') && (menuAv.querySelector('.av-initials').style.display = 'none');
    } else if (url && existing) {
      existing.src = url;
      menuAv.querySelector('.av-initials') && (menuAv.querySelector('.av-initials').style.display = 'none');
    } else if (!url && existing) {
      existing.remove();
      menuAv.querySelector('.av-initials') && (menuAv.querySelector('.av-initials').style.display = '');
    }
  }

  window._triggerAvatarUpload = function () {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.onchange = function (e) {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = function (ev) {
        const raw = new Image();
        raw.onload = function () {
          const canvas = document.createElement('canvas');
          const SIZE = 220;
          canvas.width = SIZE; canvas.height = SIZE;
          const ctx = canvas.getContext('2d');
          // Centre-crop to square
          const min = Math.min(raw.width, raw.height);
          const sx = (raw.width  - min) / 2;
          const sy = (raw.height - min) / 2;
          ctx.drawImage(raw, sx, sy, min, min, 0, 0, SIZE, SIZE);
          const dataUrl = canvas.toDataURL('image/jpeg', 0.82);
          localStorage.setItem('apex_avatar', dataUrl);
          applyAvatarToSidebar();
          applyAvatarToMenu();
        };
        raw.src = ev.target.result;
      };
      reader.readAsDataURL(file);
    };
    input.click();
  };

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
      card.setAttribute('onclick', "window.location.href='auth.html'");
      card.title = 'Sign in or create an account';
      updateSidebarPlanText('guest', gradedToday);
      // Swap upgrade button to "Create account" CTA
      const upgradeBtn = document.getElementById('upgradeBtn');
      if (upgradeBtn) {
        upgradeBtn.href = 'auth.html?mode=register';
        upgradeBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg> Create free account';
      }
      return;
    }

    card.setAttribute('onclick', 'window._sidebarToggleMenu()');

    // Avatar ring for all logged-in plans
    const avatar = document.getElementById('sidebarAvatar');
    if (avatar && (plan === 'free' || plan === 'monthly' || plan === 'pass')) {
      const wrap = document.createElement('div');
      wrap.className = 'user-avatar-wrap';
      avatar.parentNode.insertBefore(wrap, avatar);
      wrap.appendChild(avatar);
      const ring = document.createElement('div');
      ring.className = 'plan-ring ' + (plan === 'pass' ? 'plan-ring-pass' : plan === 'monthly' ? 'plan-ring-monthly' : 'plan-ring-free');
      wrap.appendChild(ring);
      const icon = document.createElement('div');
      icon.className = 'plan-icon ' + (plan === 'pass' ? 'plan-icon-pass' : plan === 'monthly' ? 'plan-icon-monthly' : 'plan-icon-free');
      icon.textContent = plan === 'pass' ? '◆' : plan === 'monthly' ? '★' : '○';
      wrap.appendChild(icon);
    }

    updateSidebarPlanText(plan, gradedToday);

    // Hide upgrade button for paid users
    const upgradeBtn = document.getElementById('upgradeBtn');
    if (upgradeBtn && plan !== 'free') upgradeBtn.style.display = 'none';

    // Re-apply avatar photo last — pages may have set textContent = initials
    // after injectSidebar ran, which wipes child nodes including our <img>
    applyAvatarToSidebar();
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

    let bc = 'badge-free', bt = '○ Free plan';
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

    const planActionRow = plan === 'free'
      ? `<div class="menu-divider"></div>
         <a class="menu-item" href="pricing.html" style="color:#2563EB;font-weight:500;">
           <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>
           Upgrade to Pro
         </a>`
      : plan === 'monthly'
      ? `<div class="menu-divider"></div>
         <a class="menu-item" href="pricing.html" style="color:#D97706;font-weight:500;">
           <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>
           Upgrade plan
         </a>
         <a class="menu-item" href="billing.html">
           <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
           Manage subscription
         </a>`
      : `<div class="menu-divider"></div>
         <a class="menu-item" href="billing.html">
           <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
           Manage subscription
         </a>`;

    const menu = document.createElement('div');
    menu.id = 'userMenu';
    menu.className = 'user-menu';
    menu.innerHTML = `
      <div class="menu-header">
        <div class="menu-header-avatar" id="menuHeaderAvatar" onclick="window._triggerAvatarUpload()" title="Change profile photo">
          <span class="av-initials">${initials}</span>
          <div class="menu-avatar-edit-overlay">
            <svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" width="15" height="15"><path d="M23 19a2 2 0 01-2 2H3a2 2 0 01-2-2V8a2 2 0 012-2h4l2-3h6l2 3h4a2 2 0 012 2z"/><circle cx="12" cy="13" r="4"/></svg>
          </div>
        </div>
        <div class="menu-header-text">
          <div class="menu-user-name">${name}</div>
          ${email ? `<div class="menu-user-email">${email}</div>` : ''}
          <span class="menu-plan-badge ${bc}">${bt}</span>
          ${memberLine}
        </div>
      </div>
      ${gradeRow}
      ${planActionRow}
      <div class="menu-divider"></div>
      <a class="menu-item" href="settings.html">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
        Settings
      </a>
      <a class="menu-item" href="learn-more.html">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        Learn more
      </a>
      <div class="menu-divider"></div>
      <div class="menu-item menu-item-danger" onclick="doLogout()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        Sign out
      </div>`;

    const bottom = document.querySelector('.sidebar-bottom');
    if (bottom) { bottom.style.position = 'relative'; bottom.appendChild(menu); }

    // Apply saved photo to the freshly-rendered menu avatar
    applyAvatarToMenu();

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
