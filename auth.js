/* LiveSport shared auth module.
 * Exposes window.LiveSportAuth.
 *
 * Page usage:
 *   const user = await LiveSportAuth.require("main");
 *   // resolves only after successful login + permission check
 *   LiveSportAuth.setupHeader(user);   // wires nav + sign-out
 */
(function () {
  "use strict";

  const USERS_URL   = "./users.json";
  const SESSION_KEY = "livesport.session";
  const ATTEMPT_KEY = "livesport.attempts";

  const PAGES = [
    { id: "main",    label: "Live Sports", href: "index.html" },
    { id: "live-tv", label: "Live TV",     href: "live-tv.html" }
  ];

  let config = null;
  let configPromise = null;

  /* ---------------- crypto ---------------- */
  const enc = new TextEncoder();
  async function sha256Hex(str) {
    const buf = await crypto.subtle.digest("SHA-256", enc.encode(str));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  }
  function safeEqual(a, b) {
    a = String(a); b = String(b);
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return d === 0;
  }
  function cryptoAvailable() {
    return typeof crypto !== "undefined" && crypto.subtle && typeof crypto.subtle.digest === "function";
  }

  /* ---------------- config ---------------- */
  async function load() {
    if (config) return config;
    if (configPromise) return configPromise;
    configPromise = (async () => {
      const res = await fetch(USERS_URL, { cache: "no-store" });
      if (!res.ok) throw new Error("Could not load users.json (HTTP " + res.status + ")");
      const json = await res.json();
      if (!json || !Array.isArray(json.users)) throw new Error('users.json is missing a "users" array');
      config = json;
      return config;
    })();
    return configPromise;
  }
  function findUser(username) {
    if (!config) return null;
    const u = String(username || "").trim().toLowerCase();
    return config.users.find(x => String(x.username || "").trim().toLowerCase() === u) || null;
  }
  async function verifyPassword(user, password) {
    if (!user) return false;
    if (user.hash && user.salt) {
      const computed = await sha256Hex(String(user.salt) + ":" + password);
      return safeEqual(computed, String(user.hash).trim().toLowerCase());
    }
    if (typeof user.password === "string" && user.password.length) {
      return safeEqual(password, user.password);
    }
    return false;
  }

  /* ---------------- session ---------------- */
  function sessionHours() {
    const h = Number(config && config.sessionHours);
    return Number.isFinite(h) && h > 0 ? h : 12;
  }
  async function makeToken(user) {
    const secret = user.hash ? String(user.hash) : String(user.password || "");
    return sha256Hex("livesport|" + String(user.username) + "|" + secret);
  }
  function getSession() {
    let raw = null;
    try { raw = localStorage.getItem(SESSION_KEY) || sessionStorage.getItem(SESSION_KEY); } catch {}
    if (!raw) return null;
    try {
      const s = JSON.parse(raw);
      if (!s || !s.u || !s.t || !s.exp) return null;
      if (Date.now() > Number(s.exp)) { clearSession(); return null; }
      return s;
    } catch { return null; }
  }
  function writeSession(user, token, remember) {
    const data = JSON.stringify({ u: String(user.username), t: token, exp: Date.now() + sessionHours() * 3600 * 1000 });
    try {
      if (remember) { localStorage.setItem(SESSION_KEY, data); sessionStorage.removeItem(SESSION_KEY); }
      else          { sessionStorage.setItem(SESSION_KEY, data); localStorage.removeItem(SESSION_KEY); }
    } catch {}
  }
  function clearSession() {
    try { localStorage.removeItem(SESSION_KEY); } catch {}
    try { sessionStorage.removeItem(SESSION_KEY); } catch {}
  }
  async function getUser() {
    const s = getSession();
    if (!s) return null;
    const user = findUser(s.u);
    if (!user) return null;
    const expected = await makeToken(user);
    return safeEqual(expected, s.t) ? user : null;
  }
  function has(pageId) {
    const s = getSession();
    if (!s) return false;
    const user = findUser(s.u);
    return user ? userCanSeePage(user, pageId) : false;
  }

  /* ---------------- permissions ---------------- */
  function userCanSeePage(user, pageId) {
    if (!user) return false;
    if (user.role === "admin") return true;
    return Array.isArray(user.pages) && user.pages.includes(pageId);
  }

  /* ---------------- throttle ---------------- */
  function getAttempts() {
    try {
      const o = JSON.parse(localStorage.getItem(ATTEMPT_KEY));
      if (o && typeof o.n === "number" && typeof o.until === "number") return o;
    } catch {}
    return { n: 0, until: 0 };
  }
  function setAttempts(o) { try { localStorage.setItem(ATTEMPT_KEY, JSON.stringify(o)); } catch {} }

  /* ---------------- gate UI ---------------- */
  function ensureGateStyles() {
    if (document.getElementById("auth-gate-style")) return;
    const style = document.createElement("style");
    style.id = "auth-gate-style";
    style.textContent = `
      .auth-gate {
        position: fixed; inset: 0; z-index: 9999;
        display: grid; place-items: center; padding: 24px;
        background: rgba(7,10,15,.92);
        backdrop-filter: blur(18px); -webkit-backdrop-filter: blur(18px);
      }
      .auth-gate[hidden] { display: none !important; }
      .auth-gate-card {
        width: min(400px, 100%);
        background: #0f151f; border: 1px solid #1f2a3a; border-radius: 20px;
        padding: 30px 28px 26px;
        box-shadow: 0 40px 90px -40px #000, inset 0 0 0 1px rgba(255,255,255,.02);
        color: #e9eff8;
        font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Inter, Arial, sans-serif;
      }
      .auth-gate-brand {
        display: flex; align-items: center; gap: 10px;
        font-weight: 800; font-size: 17px; letter-spacing: -.02em; margin-bottom: 22px;
      }
      .auth-gate-brand b { color: #22d3ee; }
      .auth-gate-brand::before {
        content: "▶"; display: grid; place-items: center;
        width: 28px; height: 28px; border-radius: 9px;
        font-size: 11px; color: #04121a;
        background: linear-gradient(135deg, #22d3ee, #38bdf8);
        box-shadow: 0 6px 18px -6px #22d3ee;
      }
      .auth-gate-card h1 { margin: 0 0 6px; font-size: 20px; letter-spacing: -.02em; }
      .auth-gate-sub { margin: 0 0 22px; font-size: 13px; color: #8b9bb1; line-height: 1.55; }
      .auth-field { display: block; margin-bottom: 14px; }
      .auth-field span { display: block; font-size: 12px; font-weight: 700; color: #8b9bb1; margin-bottom: 6px; letter-spacing: .02em; }
      .auth-field input {
        width: 100%; padding: 11px 14px; border-radius: 11px;
        border: 1px solid #2a3849; background: #151d2a; color: #e9eff8;
        font-size: 14px; outline: none; transition: .16s;
      }
      .auth-field input:focus { border-color: #22d3ee; box-shadow: 0 0 0 3px rgba(34,211,238,.13); }
      .auth-remember {
        display: flex; align-items: center; gap: 8px; font-size: 12.5px;
        color: #8b9bb1; cursor: pointer; user-select: none; margin: 2px 0 20px;
      }
      .auth-remember input { accent-color: #22d3ee; width: 15px; height: 15px; }
      .auth-btn {
        width: 100%; padding: 12px; border: 0; border-radius: 11px; cursor: pointer;
        font-size: 14px; font-weight: 800; color: #04121a;
        background: linear-gradient(135deg, #22d3ee, #38bdf8);
        transition: .15s;
      }
      .auth-btn:hover { filter: brightness(1.1); }
      .auth-btn:disabled { opacity: .6; cursor: progress; filter: none; }
      .auth-btn.secondary {
        background: transparent; color: #8b9bb1;
        border: 1px solid #2a3849; margin-top: 10px;
      }
      .auth-btn.secondary:hover { color: #e9eff8; border-color: #ff2d55; background: rgba(255,45,85,.1); }
      .auth-msg { margin-top: 14px; font-size: 12.5px; line-height: 1.5; color: #ff8098; min-height: 1em; }
      .auth-msg.ok { color: #5eead4; }
      .auth-icon { font-size: 44px; text-align: center; margin: 4px 0 14px; }
      .auth-who { color: #b8cfe6; font-weight: 700; }
      .auth-link { color: #22d3ee; text-decoration: none; font-weight: 600; }
      .auth-link:hover { text-decoration: underline; }
    `;
    document.head.appendChild(style);
  }
  function escapeHTML(s) {
    return String(s ?? "").replace(/[&<>"']/g, c =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function renderGate(html) {
    ensureGateStyles();
    let gate = document.getElementById("auth-gate");
    if (!gate) {
      gate = document.createElement("div");
      gate.id = "auth-gate";
      gate.className = "auth-gate";
      document.body.appendChild(gate);
    }
    gate.innerHTML = `<div class="auth-gate-card">${html}</div>`;
    gate.hidden = false;
    return gate;
  }
  function hideGate() {
    const gate = document.getElementById("auth-gate");
    if (gate) gate.hidden = true;
  }

  function showConfigError(err) {
    renderGate(`
      <div class="auth-gate-brand">Live<b>Sport</b></div>
      <div class="auth-icon">⚠️</div>
      <h1>Configuration error</h1>
      <p class="auth-gate-sub">${escapeHTML(err && err.message ? err.message : "Could not load users.json.")}</p>
      <button class="auth-btn secondary" onclick="location.reload()">Reload</button>
    `);
  }

  function showLoginForm(pageLabel, resolve) {
    const gate = renderGate(`
      <div class="auth-gate-brand">Live<b>Sport</b></div>
      <h1>Sign in</h1>
      <p class="auth-gate-sub">${pageLabel ? `Sign in to access <strong style="color:#e9eff8">${escapeHTML(pageLabel)}</strong>.` : "Enter your credentials to continue."}</p>
      <form id="auth-form" novalidate>
        <label class="auth-field"><span>Username</span>
          <input id="auth-u" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required>
        </label>
        <label class="auth-field"><span>Password</span>
          <input id="auth-p" type="password" autocomplete="current-password" required>
        </label>
        <label class="auth-remember"><input type="checkbox" id="auth-rem"><span>Keep me signed in</span></label>
        <button class="auth-btn" id="auth-submit" type="submit">Sign in</button>
        <div class="auth-msg" id="auth-msg" role="alert" aria-live="polite"></div>
      </form>
    `);

    const form   = gate.querySelector("#auth-form");
    const u      = gate.querySelector("#auth-u");
    const p      = gate.querySelector("#auth-p");
    const rem    = gate.querySelector("#auth-rem");
    const submit = gate.querySelector("#auth-submit");
    const msg    = gate.querySelector("#auth-msg");

    function setMsg(text, ok) { msg.textContent = text || ""; msg.classList.toggle("ok", !!ok); }
    function setBusy(b) { submit.disabled = b; submit.textContent = b ? "Signing in…" : "Sign in"; }

    u.focus();

    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      setMsg("");
      if (!cryptoAvailable()) { setMsg("Web Crypto unavailable. Serve over HTTPS (or localhost)."); return; }

      const username = u.value.trim();
      const password = p.value;
      if (!username || !password) { setMsg("Enter both a username and a password."); return; }

      const at = getAttempts();
      if (at.until && Date.now() < at.until) {
        setMsg(`Too many failed attempts. Try again in ${Math.ceil((at.until - Date.now()) / 1000)}s.`);
        return;
      }

      setBusy(true);
      try {
        const user = findUser(username);
        const ok = await verifyPassword(user, password);

        if (!ok) {
          const max  = Number(config.maxAttempts) > 0 ? Number(config.maxAttempts) : 5;
          const mins = Number(config.lockoutMinutes) > 0 ? Number(config.lockoutMinutes) : 5;
          const next = { n: at.n + 1, until: 0 };
          if (next.n >= max) {
            next.n = 0;
            next.until = Date.now() + mins * 60_000;
            setMsg(`Too many failed attempts. Locked for ${mins} minute${mins === 1 ? "" : "s"}.`);
          } else {
            setMsg(`Incorrect username or password. ${max - next.n} attempt${max - next.n === 1 ? "" : "s"} left.`);
          }
          setAttempts(next);
          p.value = ""; p.focus();
          return;
        }

        setAttempts({ n: 0, until: 0 });
        const token = await makeToken(user);
        writeSession(user, token, rem.checked);

        if (!userCanSeePage(user, currentPageId)) {
          showAccessDenied(user, currentPageLabel);
        } else {
          hideGate();
          resolve(user);
        }
      } catch (err) {
        setMsg("Sign-in failed: " + (err && err.message ? err.message : "unknown error"));
      } finally {
        setBusy(false);
      }
    });
  }

  function showAccessDenied(user, pageLabel) {
    const accessible = PAGES.filter(p => userCanSeePage(user, p.id));
    const links = accessible.map(p =>
      `<a class="auth-link" href="${p.href}">${escapeHTML(p.label)}</a>`
    ).join(", ");

    const gate = renderGate(`
      <div class="auth-gate-brand">Live<b>Sport</b></div>
      <div class="auth-icon">🔒</div>
      <h1>Access denied</h1>
      <p class="auth-gate-sub">
        Your account (<span class="auth-who">${escapeHTML(user.name || user.username)}</span>) doesn't have permission to view
        ${pageLabel ? `<strong style="color:#e9eff8">${escapeHTML(pageLabel)}</strong>` : "this page"}.
      </p>
      <p class="auth-gate-sub">
        ${accessible.length
          ? "You can access: " + links + "."
          : "Your account has no page access. Contact an administrator."}
      </p>
      <button class="auth-btn secondary" id="auth-signout">Sign out</button>
    `);
    gate.querySelector("#auth-signout").addEventListener("click", () => {
      clearSession();
      location.reload();
    });
  }

  /* ---------------- public API ---------------- */
  let currentPageId = null;
  let currentPageLabel = null;

  async function require(pageId) {
    const page = PAGES.find(p => p.id === pageId);
    currentPageId = pageId;
    currentPageLabel = page ? page.label : null;

    try {
      await load();
    } catch (err) {
      showConfigError(err);
      return new Promise(() => {});  // never resolves
    }

    const user = await getUser();
    if (user && userCanSeePage(user, pageId)) return user;
    if (user) {
      return new Promise(() => { showAccessDenied(user, currentPageLabel); });
    }
    return new Promise((resolve) => { showLoginForm(currentPageLabel, resolve); });
  }

  function setupHeader(user) {
    document.querySelectorAll("[data-auth-who]").forEach(el => {
      el.innerHTML = `Signed in as <strong>${escapeHTML(user.name || user.username)}</strong>`;
    });
    document.querySelectorAll("[data-page]").forEach(a => {
      a.hidden = !userCanSeePage(user, a.dataset.page);
    });
    document.querySelectorAll("[data-auth-signout]").forEach(btn => {
      btn.addEventListener("click", () => { clearSession(); location.reload(); });
    });
  }

  window.LiveSportAuth = {
    PAGES,
    load,
    require,
    getUser,
    has,
    userCanSeePage,
    logout: clearSession,
    setupHeader,
    getConfig: () => config,
    escapeHTML
  };
})();
