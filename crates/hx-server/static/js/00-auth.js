
"use strict";

// Same origin: the daemon serves this file and the API, so there is no host to configure and no
// CORS to arrange.
const API = "";

// ---------------------------------------------------------------------------------------------
// Authentication
//
// The daemon may require a bearer token, and this page is one of the two clients that has to send
// it. A browser cannot attach a header to a WebSocket handshake, and the bearer token must never
// ride in a URL (#24) — so before opening a socket the page trades the token for a *single-use
// ticket*: `POST /v1/ws-ticket` (a normal header-authenticated call) answers with a value that is
// good for one handshake and dies within seconds. What lands in any URL or log is then a dead
// ticket, not the credential. See `crates/hx-server/src/ws_ticket.rs`.
//
// The token itself is kept in localStorage so a reload does not lose it, and it is asked for once
// when the daemon answers 401 rather than being something a person has to know to look for first.
// Nothing else is stored here: this page owns no state the daemon does not.
const TOKEN_KEY = "hx.api.token";
const apiToken = () => localStorage.getItem(TOKEN_KEY) || "";
const setToken = (value) => {
  if (value) localStorage.setItem(TOKEN_KEY, value);
  else localStorage.removeItem(TOKEN_KEY);
  refreshAuthUI();
};

// Account login: POST /v1/login {username, password} -> {token}. Uses a raw fetch — never
// apiFetch — so no stale bearer is attached and a 401 here does not trigger the global handler.
async function doLogin(username, password) {
  let res;
  try {
    res = await fetch(`${API}/v1/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
  } catch (_) {
    throw new Error("daemon unreachable — is it running?");
  }
  if (res.status === 404) throw new Error("this daemon does not support account login (no POST /v1/login)");
  if (!res.ok) {
    let detail = "";
    try { detail = (await res.json()).error || ""; } catch (_) {}
    throw new Error(detail || (res.status === 401 ? "invalid username or password" : `login failed (HTTP ${res.status})`));
  }
  let data = null;
  try { data = await res.json(); } catch (_) {}
  if (!data || typeof data.token !== "string" || !data.token) throw new Error("login response missing token");
  return data.token;
}

// Single place that reflects auth state: panel status text + top-bar account button.
// Runs on load and on every setToken, so the button reads login/logout without a reload.
function refreshAuthUI() {
  const has = !!apiToken();
  try {
    const st = document.getElementById("token-status");
    if (st) { st.textContent = has ? "logged in" : "not logged in"; st.classList.toggle("err", false); }
  } catch (_) {}
  try {
    const btn = document.getElementById("token-button");
    if (btn) {
      btn.classList.toggle("has-token", has);
      btn.textContent = has ? "account ✓" : "login";
      btn.title = has ? "account — logged in (click to log out / switch)" : "account — log in";
    }
  } catch (_) {}
}

// Every request goes through this. A 401 is the daemon saying "auth is required" — the body
// deliberately does not distinguish a missing token from a wrong one, so neither can this.
// A fetch that throws is the daemon itself being unreachable: that feeds the connection bar so a
// dead daemon cannot look like a quiet page. Any response at all clears it.
async function apiFetch(path, init = {}) {
  const headers = Object.assign({}, init.headers || {});
  const token = apiToken();
  if (token) headers["authorization"] = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(path, Object.assign({}, init, { headers }));
  } catch (e) {
    if (typeof netDown === "function") netDown("daemon unreachable — retrying");
    throw e;
  }
  if (typeof netUp === "function") netUp();
  if (res.status === 401) {
    showError("authentication required — log in (top-right account button)");
    $("token-panel").hidden = false;
  }
  return res;
}

// Read a design token, for the one consumer that cannot use var(): canvas/terminal themes are
// painted by JS, so they ask the token layer rather than carrying literals.
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

const wsURL = async (path) => {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const bare = `${proto}//${location.host}${path}`;
  const token = apiToken();
  if (!token) return bare; // no token configured: the loopback deployment, nothing to trade
  try {
    const res = await apiFetch(`${API}/v1/ws-ticket`, { method: "POST" });
    if (!res.ok) return bare; // refused here; the handshake 401s and the retry loop keeps at it
    const body = await res.json();
    if (!body.ticket) return bare;
    return `${bare}?ticket=${encodeURIComponent(body.ticket)}`;
  } catch (_) {
    return bare;
  }
};

const $ = (id) => document.getElementById(id);
const setStatus = (text, ok) => {
  $("status-text").textContent = text;
  $("dot").classList.toggle("on", !!ok);
};
const showError = (msg) => { $("error").textContent = msg || ""; };

