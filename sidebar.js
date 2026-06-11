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
      <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M16 3L28 9.5V22.5L16 29L4 22.5V9.5L16 3Z" fill="#2d2b27"/>
        <path d="M16 3L28 9.5V22.5L16 29L4 22.5V9.5L16 3Z" stroke="white" stroke-width="2.2" stroke-linejoin="round"/>
        <path d="M16 9L23 21H9L16 9Z" fill="#d4d0c8"/>
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
    <a class="nav-item" href="mock-interview.html" data-page="mock">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 1a3 3 0 00-3 3v8a3 3 0 006 0V4a3 3 0 00-3-3z"/><path d="M19 10v2a7 7 0 01-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></svg>
      Mock Interview
    </a>
    <a class="nav-item" href="saved-questions.html" data-page="saved">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21l-7-5-7 5V5a2 2 0 012-2h10a2 2 0 012 2z"/></svg>
      Saved Questions
    </a>

    <div class="nav-section-label" style="margin-top:10px;">Social</div>
    <a class="nav-item" href="you.html" data-page="you">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M20 21a8 8 0 1 0-16 0"/></svg>
      You
    </a>
    <a class="nav-item" href="feed.html" data-page="feed">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><path d="M8 10h8"/><path d="M8 14h5"/></svg>
      Feed
    </a>
    <a class="nav-item" href="friends.html" data-page="friends">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
      Friends
    </a>
    <a class="nav-item" href="party.html" data-page="party">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="23" y1="11" x2="17" y2="11"/><line x1="20" y1="8" x2="20" y2="14"/></svg>
      Study Party
    </a>

    <div class="nav-section-label" style="margin-top:10px;">Topics</div>
    <a class="nav-item" href="practice-screen.html?topic=Accounting">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 21v-6"/><path d="M12 9V3"/><path d="M3 15h18"/><path d="M3 9h18"/><rect width="18" height="18" x="3" y="3" rx="2"/></svg>
      Accounting
    </a>
    <a class="nav-item" href="practice-screen.html?topic=Enterprise_Value">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21V8l6-4 6 4v13"/><path d="M3 21h12"/><path d="M7 12h.01M7 16h.01M11 12h.01M11 16h.01"/><circle cx="17.5" cy="15.5" r="3"/><line x1="19.6" y1="17.6" x2="22" y2="20"/><text x="17.5" y="17" text-anchor="middle" font-size="4" font-weight="700" font-family="sans-serif" fill="currentColor" stroke="none">$</text></svg>
      Enterprise Value
    </a>
    <a class="nav-item" href="practice-screen.html?topic=Valuation">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 6h8"/><path d="M12 16h6"/><path d="M3 3v16a2 2 0 0 0 2 2h16"/><path d="M8 11h7"/></svg>
      Valuation
    </a>
    <a class="nav-item" href="practice-screen.html?topic=DCF">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16v5"/><path d="M16 14v7"/><path d="M20 10v11"/><path d="m22 3-8.646 8.646a.5.5 0 0 1-.708 0L9.354 8.354a.5.5 0 0 0-.707 0L2 15"/><path d="M4 18v3"/><path d="M8 14v7"/></svg>
      Discounted Cash Flow
    </a>
    <a class="nav-item" href="practice-screen.html?topic=Mergers_MA">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m11 17 2 2a1 1 0 1 0 3-3"/><path d="m14 14 2.5 2.5a1 1 0 1 0 3-3l-3.88-3.88a3 3 0 0 0-4.24 0l-.88.88a1 1 0 1 1-3-3l2.81-2.81a5.79 5.79 0 0 1 7.06-.87l.47.28a2 2 0 0 0 1.42.25L21 4"/><path d="m21 3 1 11h-2"/><path d="M3 3 2 14l6.5 6.5a1 1 0 1 0 3-3"/><path d="M3 4h8"/></svg>
      Mergers &amp; Acquisitions
    </a>
    <a class="nav-item" href="practice-screen.html?topic=LBO">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 17h3v2a1 1 0 0 0 1 1h2a1 1 0 0 0 1-1v-3a3.16 3.16 0 0 0 2-2h1a1 1 0 0 0 1-1v-2a1 1 0 0 0-1-1h-1a5 5 0 0 0-2-4V3a4 4 0 0 0-3.2 1.6l-.3.4H11a6 6 0 0 0-6 6v1a5 5 0 0 0 2 4v3a1 1 0 0 0 1 1h2a1 1 0 0 0 1-1z"/><path d="M16 10h.01"/><path d="M2 8v1a2 2 0 0 0 2 2h1"/></svg>
      Leveraged Buyouts
    </a>
  </nav>

  <div class="sidebar-bottom">
    <a href="pricing.html" class="upgrade-btn" id="upgradeBtn">
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

    // Apply cached identity + plan IMMEDIATELY (before the API call resolves)
    // so the sidebar shows the right state on the very first paint.
    try {
      const cachedPlan  = localStorage.getItem('apex_plan');
      const cachedGrad  = parseInt(localStorage.getItem('apex_graded_today') || '0');
      // Safe name parse — getApexName() not yet defined here so inline it
      let cachedName = '';
      try {
        const _r = localStorage.getItem('apex_user');
        if (_r && _r !== 'undefined' && _r !== 'null') {
          const _p = JSON.parse(_r);
          cachedName = (typeof _p === 'object' && _p !== null) ? (_p.name || '') : (String(_p) || '');
        }
        if (!cachedName) cachedName = localStorage.getItem('apex_name') || '';
      } catch(e) { cachedName = localStorage.getItem('apex_name') || ''; }
      if (cachedName) {
        const nm = document.getElementById('sidebarUserName');
        if (nm) nm.textContent = cachedName;
        const av = document.getElementById('sidebarAvatar');
        if (av && !av.querySelector('img')) {
          const initials = cachedName.split(' ').map(w => w[0]).join('').slice(0,2).toUpperCase();
          av.textContent = initials;
        }
      }
      if (cachedPlan) initSidebarMenu(cachedPlan, cachedGrad);
      else if (!localStorage.getItem('apex_token')) initSidebarMenu('guest', 0);
    } catch(e) {}
  }

  // ── AVATAR HELPERS ────────────────────────────────────────
  function getSidebarUserId() {
    try {
      const t = localStorage.getItem('apex_token');
      if (!t) return null;
      const p = JSON.parse(atob(t.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));
      return p.userId;
    } catch(e) { return null; }
  }

  function getAvatarUrl() {
    const uid = getSidebarUserId();
    return uid ? localStorage.getItem('apex_avatar_' + uid) : null;
  }

  function applyAvatarToSidebar() {
    const url = getAvatarUrl();
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
      el.style.position = 'relative';
    } else {
      if (existing) existing.remove();
      // Try fetching from server if not cached
      const uid = getSidebarUserId();
      const token = localStorage.getItem('apex_token');
      if (uid && token) {
        fetch('/api/auth/avatar', { headers: {'Authorization':'Bearer '+token}})
          .then(r=>r.json()).then(data => {
            if (data.avatarData) {
              localStorage.setItem('apex_avatar_'+uid, data.avatarData);
              applyAvatarToSidebar();
            }
          }).catch(()=>{});
      }
    }
  }

  function applyAvatarToMenu() {
    const url = getAvatarUrl();
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
          const uid = getSidebarUserId();
          const token = localStorage.getItem('apex_token');
          if (uid && token) {
            fetch('/api/auth/save-avatar', {
              method: 'POST',
              headers: {'Content-Type':'application/json','Authorization':'Bearer '+token},
              body: JSON.stringify({avatarData: dataUrl})
            }).then(()=>{
              localStorage.setItem('apex_avatar_'+uid, dataUrl);
              applyAvatarToSidebar();
              applyAvatarToMenu();
            }).catch(()=>{
              localStorage.setItem('apex_avatar_'+uid, dataUrl);
              applyAvatarToSidebar();
              applyAvatarToMenu();
            });
          }
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
      el.textContent = 'Recruiting Pass';
      el.style.background = 'linear-gradient(135deg, #78350f, #d97706, #fbbf24, #b45309, #92400e, #d97706)';
      el.style.backgroundSize = '300% 300%';
      el.style.webkitBackgroundClip = 'text';
      el.style.webkitTextFillColor = 'transparent';
      el.style.backgroundClip = 'text';
      el.style.animation = 'badgePassShimmer 5s ease infinite';
    } else if (plan === 'monthly') {
      el.textContent = 'Pro plan';
      el.style.background = 'linear-gradient(135deg, #1e3a8a, #3b82f6, #6366f1, #1e40af, #1e3a8a)';
      el.style.backgroundSize = '300% 300%';
      el.style.webkitBackgroundClip = 'text';
      el.style.webkitTextFillColor = 'transparent';
      el.style.backgroundClip = 'text';
      el.style.animation = 'badgeMonthlyShift 6s ease infinite';
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

    // Cache for instant render on next page nav
    try {
      if (plan && plan !== 'guest') localStorage.setItem('apex_plan', plan);
      if (typeof gradedToday === 'number') localStorage.setItem('apex_graded_today', String(gradedToday));
    } catch(e) {}

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
      // Idempotent: only wrap if not already wrapped
      let wrap = avatar.closest('.user-avatar-wrap');
      if (!wrap) {
        wrap = document.createElement('div');
        wrap.className = 'user-avatar-wrap';
        avatar.parentNode.insertBefore(wrap, avatar);
        wrap.appendChild(avatar);
      }
      // Remove any prior ring/icon then re-create matching the current plan
      wrap.querySelectorAll('.plan-ring, .plan-icon').forEach(el => el.remove());
      const ring = document.createElement('div');
      ring.className = 'plan-ring ' + (plan === 'pass' ? 'plan-ring-pass' : plan === 'monthly' ? 'plan-ring-monthly' : 'plan-ring-free');
      wrap.appendChild(ring);
      const icon = document.createElement('div');
      icon.className = 'plan-icon ' + (plan === 'pass' ? 'plan-icon-pass' : plan === 'monthly' ? 'plan-icon-monthly' : 'plan-icon-free');
      icon.textContent = plan === 'pass' ? '◆' : plan === 'monthly' ? '★' : '○';
      wrap.appendChild(icon);
    }

    updateSidebarPlanText(plan, gradedToday);

    // Update sidebar name + initials from stored value
    const _raw = localStorage.getItem('apex_user');
    let _name = '';
    try {
      if (_raw && _raw !== 'undefined' && _raw !== 'null') {
        const _p = JSON.parse(_raw);
        _name = (typeof _p === 'object' && _p !== null) ? (_p.name || '') : (String(_p) || '');
      }
    } catch(e) {}
    if (!_name || _name === 'undefined') _name = localStorage.getItem('apex_name') || '';
    if (_name) {
      const nmEl = document.getElementById('sidebarUserName');
      if (nmEl) nmEl.textContent = _name;
      const avEl = document.getElementById('sidebarAvatar');
      if (avEl && !avEl.querySelector('img')) {
        avEl.textContent = _name.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
      }
    }

    // Upgrade button: show for free + monthly, hide for pass
    const upgradeBtn = document.getElementById('upgradeBtn');
    if (upgradeBtn) {
      if (plan === 'pass') {
        upgradeBtn.style.display = 'none';
      } else if (plan === 'monthly') {
        upgradeBtn.style.display = '';
        upgradeBtn.className = 'upgrade-btn pass-btn';
        upgradeBtn.textContent = 'Get Recruiting Pass';
      } else {
        upgradeBtn.style.display = '';
        upgradeBtn.className = 'upgrade-btn';
        upgradeBtn.textContent = 'Upgrade to Pro';
      }
    }

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
    const _rawUser    = localStorage.getItem('apex_user');
    let name = '', email = localStorage.getItem('apex_email') || '';
    try {
      if (_rawUser && _rawUser !== 'undefined' && _rawUser !== 'null') {
        const parsed = JSON.parse(_rawUser);
        name = (typeof parsed === 'object' && parsed !== null) ? (parsed.name || '') : (String(parsed) || '');
        if (!email && parsed?.email) email = parsed.email;
      }
    } catch(e) {
      // plain string stored (old format) — only use if it doesn't look like garbage
      if (_rawUser && _rawUser !== 'undefined' && _rawUser !== 'null' && !_rawUser.startsWith('{')) {
        name = _rawUser;
      }
    }
    // Always fall back to apex_name
    if (!name || name === 'undefined') name = localStorage.getItem('apex_name') || '—';
    // Also update sidebar elements while we're here
    const nmEl = document.getElementById('sidebarUserName');
    if (nmEl && name && name !== '—') nmEl.textContent = name;
    const avEl = document.getElementById('sidebarAvatar');
    if (avEl && !avEl.querySelector('img') && name && name !== '—') {
      avEl.textContent = name.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
    }
    const memberSince = window._memberSince;

    const initials = name.split(' ').map(w => w[0]).join('').slice(0,2).toUpperCase();

    let bc = 'badge-free', bt = '○ Free plan';
    if (plan === 'monthly') { bc = 'badge-monthly'; bt = 'Pro'; }
    if (plan === 'pass')    { bc = 'badge-pass';    bt = 'Recruiting Pass'; }

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
         <a class="menu-item menu-item-upgrade-pro" href="pricing.html" style="font-weight:600;background:linear-gradient(135deg,#1e3a8a,#3b82f6,#6366f1,#1e40af,#1e3a8a);background-size:300% 300%;-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;animation:badgeMonthlyShift 6s ease infinite;">
           Upgrade to Pro
         </a>`
      : plan === 'monthly'
      ? `<div class="menu-divider"></div>
         <a class="menu-item menu-item-upgrade-pass" href="pricing.html" style="font-weight:600;background:linear-gradient(135deg,#78350f,#d97706,#fbbf24,#b45309,#92400e,#d97706);background-size:400% 400%;-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;animation:badgePassShimmer 5s ease infinite;">
           Get Recruiting Pass
         </a>
         <a class="menu-item" href="settings.html?tab=billing">
           <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
           Manage subscription
         </a>`
      : `<div class="menu-divider"></div>
         <a class="menu-item" href="settings.html?tab=billing">
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
      <a class="menu-item" href="bug-report.html">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="8" height="14" x="8" y="6" rx="4"/><path d="m19 7-3 2"/><path d="m5 7 3 2"/><path d="m19 19-3-2"/><path d="m5 19 3-2"/><path d="M20 13h-4"/><path d="M4 13h4"/><path d="m10 4 1 2"/><path d="m14 4-1 2"/></svg>
        Report an issue
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
    const uid = getSidebarUserId();
    if (uid) localStorage.removeItem('apex_avatar_' + uid);
    localStorage.removeItem('apex_token');
    localStorage.removeItem('apex_user');
    localStorage.removeItem('apex_name');
    localStorage.removeItem('apex_plan');
    localStorage.removeItem('apex_graded_today');
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
  // Safe read of apex_user — handles both old plain-string and new JSON object formats
  function getApexName() {
    try {
      const raw = localStorage.getItem('apex_user');
      if (!raw || raw === 'undefined' || raw === 'null') return localStorage.getItem('apex_name') || '';
      const parsed = JSON.parse(raw);
      if (typeof parsed === 'object' && parsed !== null) return parsed.name || localStorage.getItem('apex_name') || '';
      return String(parsed) || localStorage.getItem('apex_name') || '';
    } catch(e) {
      return localStorage.getItem('apex_name') || '';
    }
  }
  window.getApexName = getApexName;

  window.initSidebarMenu      = initSidebarMenu;
  window.updateSidebarPlanText = updateSidebarPlanText;

})();
