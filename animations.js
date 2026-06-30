/* ── APEX SHARED ANIMATIONS ─────────────────────────────────
   Used by: landing.html, pricing.html
   Exports (global):
     apexShowVignette(plan)
     apexHideVignette()
     apexLaunchWhirlpool(plan, billingPeriod, token, showToast)
     apexLaunchFreeWash(dest)
   Requires overlay HTML injected by each page (see bottom comment)
──────────────────────────────────────────────────────────── */

// ── STATE ────────────────────────────────────────────────────
var _apexWhirlpoolActive = false;
var _apexVigTarget = 0, _apexVigCurrent = 0, _apexVigPlan = null;

// ── VIGNETTE ─────────────────────────────────────────────────
function apexShowVignette(plan) {
  _apexVigPlan = plan;
  _apexVigTarget = 1;
  var overlay = document.getElementById('apexVignetteOverlay');
  if (!overlay) return;
  overlay.style.display = 'block';
  _apexDrawVignette();
  requestAnimationFrame(_apexAnimateVignette);
}

function apexHideVignette() {
  _apexVigTarget = 0;
}

function _apexAnimateVignette() {
  _apexVigCurrent += (_apexVigTarget - _apexVigCurrent) * 0.1;
  var overlay = document.getElementById('apexVignetteOverlay');
  if (!overlay) return;
  overlay.style.opacity = _apexVigCurrent;
  _apexDrawVignette();
  if (_apexVigCurrent > 0.002) requestAnimationFrame(_apexAnimateVignette);
  else { _apexVigCurrent = 0; overlay.style.display = 'none'; }
}

function _apexDrawVignette() {
  var canvas = document.getElementById('apexVignetteCanvas');
  if (!canvas) return;
  var W = canvas.width = window.innerWidth, H = canvas.height = window.innerHeight;
  var ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, W, H);
  var isPro = _apexVigPlan === 'monthly';
  var c1 = isPro ? 'rgba(37,99,235,' : 'rgba(217,119,6,';
  var c2 = isPro ? 'rgba(30,58,138,' : 'rgba(146,64,14,';
  var gL = ctx.createLinearGradient(0,0,W*.38,0); gL.addColorStop(0,c2+'0.55)'); gL.addColorStop(.5,c1+'0.2)'); gL.addColorStop(1,'transparent'); ctx.fillStyle=gL; ctx.fillRect(0,0,W*.38,H);
  var gR = ctx.createLinearGradient(W,0,W*.62,0); gR.addColorStop(0,c2+'0.55)'); gR.addColorStop(.5,c1+'0.2)'); gR.addColorStop(1,'transparent'); ctx.fillStyle=gR; ctx.fillRect(W*.62,0,W*.38,H);
  var gT = ctx.createLinearGradient(0,0,0,H*.22); gT.addColorStop(0,c1+'0.18)'); gT.addColorStop(1,'transparent'); ctx.fillStyle=gT; ctx.fillRect(0,0,W,H*.22);
  var gB = ctx.createLinearGradient(0,H,0,H*.78); gB.addColorStop(0,c1+'0.18)'); gB.addColorStop(1,'transparent'); ctx.fillStyle=gB; ctx.fillRect(0,H*.78,W,H*.22);
}

// ── WHIRLPOOL LOOP (infinite, stopped by flag) ────────────────
function _apexStartWhirlpoolLoop(plan) {
  _apexWhirlpoolActive = true;
  var canvas = document.getElementById('apexWhirlpoolCanvas');
  if (!canvas) return;
  var isPro = plan === 'monthly';
  var color1 = isPro ? '#2563EB' : '#D97706';
  var color2 = isPro ? '#60A5FA' : '#FDE68A';
  var color3 = isPro ? '#1E3A8A' : '#92400E';
  var bgBase = isPro ? '#0f1b40' : '#1c0e00';
  var W = canvas.width = window.innerWidth, H = canvas.height = window.innerHeight;
  var cx = W/2, cy = H/2, ctx = canvas.getContext('2d'), start = performance.now();
  var particles = Array.from({length:220}, function(_,i) {
    var frac = i/220;
    return { angle: frac*Math.PI*2*5, radius: 80+Math.random()*(Math.max(W,H)*.7), speed: 2+Math.random()*3, size: 2+Math.random()*5, alpha: .4+Math.random()*.6, color:[color1,color2,color3][Math.floor(Math.random()*3)], trail:[] };
  });
  function draw(now) {
    if (!_apexWhirlpoolActive) return;
    var elapsed = Math.min(now - start, 1800), tRaw = elapsed/1800;
    var tIn = tRaw*tRaw*tRaw, tFade = 1-Math.pow(1-Math.min(elapsed/400,1),2);
    var spinBoost = 1+tIn*4, shrink = Math.max(1-tIn*.7,.25);
    ctx.fillStyle=bgBase; ctx.globalAlpha=tFade*.92; ctx.fillRect(0,0,W,H); ctx.globalAlpha=1;
    var gr = tIn*220;
    if (gr>0) { var grd=ctx.createRadialGradient(cx,cy,0,cx,cy,gr); grd.addColorStop(0,color2+'cc'); grd.addColorStop(.4,color1+'66'); grd.addColorStop(1,'transparent'); ctx.globalAlpha=tIn*.7; ctx.fillStyle=grd; ctx.beginPath(); ctx.arc(cx,cy,gr,0,Math.PI*2); ctx.fill(); ctx.globalAlpha=1; }
    particles.forEach(function(p) {
      p.angle += p.speed*.018*spinBoost;
      var r=p.radius*shrink, x=cx+Math.cos(p.angle)*r, y=cy+Math.sin(p.angle)*r;
      p.trail.push({x:x,y:y}); if(p.trail.length>10) p.trail.shift();
      if(p.trail.length>1){ ctx.beginPath(); ctx.moveTo(p.trail[0].x,p.trail[0].y); for(var t=1;t<p.trail.length;t++) ctx.lineTo(p.trail[t].x,p.trail[t].y); ctx.strokeStyle=p.color; ctx.lineWidth=p.size*.6; ctx.globalAlpha=p.alpha*tFade; ctx.stroke(); ctx.globalAlpha=1; }
      ctx.beginPath(); ctx.arc(x,y,p.size*(1-tIn*.5),0,Math.PI*2); ctx.fillStyle=p.color; ctx.globalAlpha=p.alpha*tFade; ctx.fill(); ctx.globalAlpha=1;
    });
    requestAnimationFrame(draw);
  }
  requestAnimationFrame(draw);
}

// ── WHIRLPOOL PUBLIC (async Stripe fetch) ─────────────────────
// showToast(msg) — pass page-specific toast function
async function apexLaunchWhirlpool(plan, billingPeriod, token, showToast) {
  var currentPlan = localStorage.getItem('apex_plan') || 'free';

  // Guard: already on pass → dashboard regardless of what they clicked
  if (token && currentPlan === 'pass') {
    window.location.href = 'dashboard.html';
    return;
  }
  // Guard: pro clicking pro → dashboard
  if (token && currentPlan === 'monthly' && plan === 'monthly') {
    window.location.href = 'dashboard.html';
    return;
  }
  var overlay = document.getElementById('apexWhirlpoolOverlay');
  var label   = document.getElementById('apexWhirlpoolText');
  if (!overlay) return;

  overlay.style.display = 'flex';
  overlay.style.opacity = '1';
  void overlay.offsetHeight;
  setTimeout(function() { label.style.opacity = '1'; }, 300);
  _apexStartWhirlpoolLoop(plan);

  var animStart = Date.now();
  var MIN_ANIM_MS = 2000;

  if (!token) {
    setTimeout(function() {
      window.location.href = 'auth.html?mode=register&plan=' + plan + '&period=' + billingPeriod;
    }, MIN_ANIM_MS);
    return;
  }

  // Running inside the native iOS/Android shell → use platform IAP (RevenueCat)
  // instead of Stripe Checkout. Web visitors fall through to the existing flow.
  if (window.Capacitor && window.Capacitor.isNativePlatform && window.Capacitor.isNativePlatform()) {
    try {
      await apexNativePurchase(plan, billingPeriod, token, animStart, MIN_ANIM_MS, overlay, label, showToast);
    } catch(e) {
      _apexWhirlpoolActive = false;
      overlay.style.display = 'none'; label.style.opacity = '0';
      if (showToast) showToast('Could not start checkout. Please try again.');
    }
    return;
  }

  try {
    var r = await fetch('/api/stripe/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ plan: plan, period: billingPeriod })
    });
    var data = await r.json();
    if (data.url) {
      var elapsed = Date.now() - animStart;
      setTimeout(function() { window.location.href = data.url; }, Math.max(0, MIN_ANIM_MS - elapsed));
    } else {
      _apexWhirlpoolActive = false;
      overlay.style.display = 'none'; label.style.opacity = '0';
      if (showToast) showToast(data.error || 'Could not start checkout. Please try again.');
    }
  } catch(e) {
    _apexWhirlpoolActive = false;
    overlay.style.display = 'none'; label.style.opacity = '0';
    if (showToast) showToast('Something went wrong. Please try again.');
  }
}

// ── NATIVE IAP (RevenueCat, iOS/Android app only) ───────────────
// PRODUCT_MAP must match the product identifiers you create in App Store
// Connect / Play Console, and the entitlement/offering setup in the
// RevenueCat dashboard. monthly = Pro, pass = Recruiting Pass.
var APEX_RC_PRODUCT_MAP = {
  monthly: { week: 'pro_weekly', month: 'pro_monthly' },
  pass:    { week: 'pass_weekly', month: 'pass_monthly' }
};

// Call once at app boot (e.g. in dashboard.html / on auth) so RevenueCat
// ties purchases to the same user id your backend already uses — this is
// what lets the webhook map a purchase back to the right account.
async function apexConfigureRevenueCat(token, userId) {
  if (!window.Capacitor || !window.Capacitor.isNativePlatform || !window.Capacitor.isNativePlatform()) return;
  var Purchases = window.Capacitor.Plugins && window.Capacitor.Plugins.Purchases;
  if (!Purchases || !userId) return;
  try {
    await Purchases.configure({
      apiKey: 'YOUR_REVENUECAT_PUBLIC_IOS_API_KEY', // from RevenueCat dashboard → Project Settings → API Keys
      appUserID: String(userId)
    });
  } catch(e) { /* already configured, or plugin unavailable — non-fatal */ }
}

async function apexNativePurchase(plan, billingPeriod, token, animStart, MIN_ANIM_MS, overlay, label, showToast) {
  var Purchases = window.Capacitor.Plugins && window.Capacitor.Plugins.Purchases;
  if (!Purchases) throw new Error('Purchases plugin unavailable');

  // pricing.html doesn't load sidebar.js (which normally configures
  // RevenueCat on boot), so make sure it's configured before purchasing.
  try {
    var payload = JSON.parse(atob(token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));
    if (payload && payload.userId) {
      await Purchases.configure({
        apiKey: 'YOUR_REVENUECAT_PUBLIC_IOS_API_KEY',
        appUserID: String(payload.userId)
      });
    }
  } catch(e) { /* may already be configured from another page — non-fatal */ }

  var period = billingPeriod === 'weekly' ? 'week' : 'month';
  var productId = (APEX_RC_PRODUCT_MAP[plan] || {})[period];
  if (!productId) throw new Error('Unknown product for ' + plan + '/' + billingPeriod);

  var offerings = await Purchases.getOfferings();
  var pkg = null;
  var current = offerings && offerings.current;
  if (current && current.availablePackages) {
    pkg = current.availablePackages.find(function(p) {
      return p.product && p.product.identifier === productId;
    });
  }
  if (!pkg) throw new Error('Product not found in offerings: ' + productId);

  var result = await Purchases.purchasePackage({ aPackage: pkg });
  // result.customerInfo.entitlements tells us what unlocked — confirm with
  // our backend immediately for instant UI feedback (the RevenueCat webhook
  // is the durable source of truth for renewals/cancellations/refunds).
  try {
    await fetch('/api/iap/confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({
        plan: plan,
        productId: productId,
        rcAppUserId: result.customerInfo ? result.customerInfo.originalAppUserId : null
      })
    });
  } catch(e) { /* webhook will still reconcile this within seconds */ }

  var elapsed = Date.now() - animStart;
  setTimeout(function() { window.location.href = 'dashboard.html?upgraded=1'; }, Math.max(0, MIN_ANIM_MS - elapsed));
}

// ── FREE WASH ─────────────────────────────────────────────────
var _apexFinanceSymbols = ['$','€','£','¥','%','∑','∂','π','∫','±','×','÷','IRR','NPV','EBITDA','DCF','P/E','EV','ROI','WACC','β','α','Δ','√','≈','∞','LBO','M&A','IPO','10x','2.5x','8%','15%','3.2x'];

function apexLaunchFreeWash(dest) {
  var overlay = document.getElementById('apexFreeWashOverlay');
  var canvas  = document.getElementById('apexFreeWashCanvas');
  var label   = document.getElementById('apexFreeWashText');
  if (!overlay) return;
  overlay.style.display = 'flex';
  overlay.style.opacity = '1';
  void overlay.offsetHeight;
  var W = canvas.width = window.innerWidth, H = canvas.height = window.innerHeight;
  var ctx = canvas.getContext('2d'), DURATION = 1800, start = performance.now();
  var symbols = Array.from({length:60}, function() {
    return { text: _apexFinanceSymbols[Math.floor(Math.random()*_apexFinanceSymbols.length)], x:Math.random()*W, y:Math.random()*H, size:14+Math.random()*28, alpha:.06+Math.random()*.18, vx:(Math.random()-.5)*.4, vy:-.3-Math.random()*.5, rotation:(Math.random()-.5)*.4, angle:(Math.random()-.5)*1.2 };
  });
  function drawFrame(now) {
    var elapsed=now-start, t=Math.min(elapsed/DURATION,1);
    var te = t<.5 ? 2*t*t : 1-Math.pow(-2*t+2,2)/2;
    ctx.clearRect(0,0,W,H);
    ctx.fillStyle='rgba(20,20,20,'+(te*.96)+')'; ctx.fillRect(0,0,W,H);
    symbols.forEach(function(s) {
      s.x+=s.vx; s.y+=s.vy; s.angle+=s.rotation*.01;
      ctx.save(); ctx.translate(s.x,s.y); ctx.rotate(s.angle);
      ctx.font='600 '+s.size+'px "DM Sans",sans-serif';
      ctx.fillStyle='rgba(160,160,160,'+(s.alpha*te)+')';
      ctx.fillText(s.text,0,0); ctx.restore();
      if(s.y<-60) s.y=H+20; if(s.x<-60) s.x=W+20; if(s.x>W+60) s.x=-20;
    });
    if(t<1) requestAnimationFrame(drawFrame);
    else window.location.href = dest;
  }
  requestAnimationFrame(drawFrame);
  setTimeout(function() { label.style.opacity='1'; }, 350);
}

// ── RESET (bfcache pageshow) ──────────────────────────────────
window.addEventListener('pageshow', function() {
  _apexWhirlpoolActive = false;
  _apexVigCurrent = 0; _apexVigTarget = 0;
  ['apexWhirlpoolOverlay','apexFreeWashOverlay','apexVignetteOverlay'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) { el.style.display = 'none'; el.style.opacity = ''; }
  });
  var wl = document.getElementById('apexWhirlpoolText'); if (wl) wl.style.opacity = '0';
  var fl = document.getElementById('apexFreeWashText');  if (fl) fl.style.opacity = '0';
});

/*
── REQUIRED HTML (paste before </body> on each page) ──────────

<div id="apexVignetteOverlay" style="display:none;position:fixed;inset:0;z-index:100;pointer-events:none;transition:opacity .35s ease;opacity:0;">
  <canvas id="apexVignetteCanvas" style="position:absolute;inset:0;width:100%;height:100%;"></canvas>
</div>
<div id="apexWhirlpoolOverlay" style="display:none;position:fixed;inset:0;z-index:99999;align-items:center;justify-content:center;">
  <canvas id="apexWhirlpoolCanvas" style="position:absolute;inset:0;width:100%;height:100%;"></canvas>
  <div id="apexWhirlpoolText" style="position:relative;z-index:1;font-family:'DM Serif Display',serif;font-size:22px;color:white;letter-spacing:-.3px;text-shadow:0 2px 20px rgba(0,0,0,.5);opacity:0;transition:opacity .4s ease .3s;">Taking you to checkout…</div>
</div>
<div id="apexFreeWashOverlay" style="display:none;position:fixed;inset:0;z-index:99999;align-items:center;justify-content:center;">
  <canvas id="apexFreeWashCanvas" style="position:absolute;inset:0;width:100%;height:100%;"></canvas>
  <div id="apexFreeWashText" style="position:relative;z-index:1;font-family:'DM Serif Display',serif;font-size:22px;color:white;letter-spacing:-.3px;text-shadow:0 2px 20px rgba(0,0,0,.5);opacity:0;transition:opacity .4s ease .3s;">Starting your free account…</div>
</div>
<script src="animations.js"></script>
*/
