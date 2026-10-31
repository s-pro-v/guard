"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

// Konfiguracja kluczy i zabezpieczeń
const DEFAULT_HASH = "3cdf2dabfe18fb4d0e1f39fc86f836ed20ef0510d0f373b8071417906842bb93";
const MASTER_KEY = (process.env.MASTER_KEY || DEFAULT_HASH).trim();
const JWT_SECRET = process.env.JWT_SECRET || "lks_render_default_secret_key_change_me_987654";
const TOKEN_EXPIRES_IN = process.env.TOKEN_EXPIRES_IN || "24h";

// Parsowanie listy dozwolonych skrótów SHA-256 z ENV
// Format: "hash1:ROLA1,hash2:ROLA2" lub pojedynczy klucz
const allowedHashes = {
    [DEFAULT_HASH]: "ROOT_SYS"
};

if (MASTER_KEY && !allowedHashes[MASTER_KEY]) {
    // Jeśli podano 64-znakowy hash SHA-256
    if (/^[a-f0-9]{64}$/i.test(MASTER_KEY)) {
        allowedHashes[MASTER_KEY.toLowerCase()] = "ROOT_SYS";
    } else {
        // Jeśli podano hasło w tekście, haszujemy do SHA-256
        const hashed = crypto.createHash("sha256").update(MASTER_KEY).digest("hex");
        allowedHashes[hashed] = "ROOT_SYS";
    }
}

if (process.env.EXTRA_KEYS) {
    // Możliwość dodania wielu kluczy w zmiennej środowiskowej: "klucz1,klucz2"
    process.env.EXTRA_KEYS.split(",").forEach(item => {
        const trimmed = item.trim();
        if (!trimmed) return;
        const h = /^[a-f0-9]{64}$/i.test(trimmed)
            ? trimmed.toLowerCase()
            : crypto.createHash("sha256").update(trimmed).digest("hex");
        allowedHashes[h] = "USER_NODE";
    });
}

// Konfiguracja CORS (dostęp dla stron zewnętrznych np. carrd.co, github.io)
const allowedOrigins = process.env.ALLOWED_ORIGINS;
app.use(cors({
    origin: function (origin, callback) {
        if (!allowedOrigins || allowedOrigins === "*" || !origin) {
            return callback(null, true);
        }
        const list = allowedOrigins.split(",").map(o => o.trim().toLowerCase());
        const match = list.some(o => o === "*" || origin.toLowerCase().includes(o));
        if (match) return callback(null, true);
        return callback(null, true); // Domyślnie zezwalaj dla autoryzacji stron
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

// Pomocnicza funkcja określania adresu bazowego serwera (na Renderze x-forwarded-proto/host)
function getServerUrl(req) {
    if (process.env.SERVER_URL) {
        return process.env.SERVER_URL.replace(/\/$/, "");
    }
    const proto = req.headers["x-forwarded-proto"] || req.protocol || "http";
    const host = req.headers["x-forwarded-host"] || req.headers.host;
    return `${proto}://${host}`;
}

// 1. Healthcheck dla Render.com
app.get("/healthz", (req, res) => {
    res.status(200).json({
        status: "ok",
        service: "LKS_GUARD_RENDER",
        uptime: Math.floor(process.uptime()),
        timestamp: new Date().toISOString()
    });
});

// 2. Logowanie / Autoryzacja i wygenerowanie podpisanego tokenu
app.post("/api/auth/login", (req, res) => {
    try {
        const { key, hash } = req.body || {};
        let inputHash = (hash || "").trim().toLowerCase();

        if (!inputHash && key) {
            const raw = String(key).trim();
            // Jeśli użytkownik wpisał gotowy hash 64 hex znaki
            if (/^[a-f0-9]{64}$/i.test(raw)) {
                inputHash = raw.toLowerCase();
            } else {
                inputHash = crypto.createHash("sha256").update(raw).digest("hex");
            }
        }

        if (!inputHash) {
            return res.status(400).json({
                success: false,
                code: "ERR_MISSING_CREDENTIALS",
                message: "Brak wektora inicjalizacyjnego lub hasha."
            });
        }

        const role = allowedHashes[inputHash];
        if (!role) {
            return res.status(401).json({
                success: false,
                code: "ERR_ACCESS_DENIED",
                message: "Niezgodność sumy kontrolnej SHA-256!"
            });
        }

        // Podpisanie bezpiecznego tokenu JWT
        const payload = {
            sub: "oxy_user",
            role: role,
            hashPrefix: inputHash.slice(0, 8),
            issuedAt: Date.now()
        };

        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRES_IN });
        const decoded = jwt.decode(token);

        return res.json({
            success: true,
            role: role,
            token: token,
            expiresAt: decoded.exp * 1000,
            expiresIn: TOKEN_EXPIRES_IN
        });
    } catch (err) {
        console.error("Auth error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

let lastGlobalLogoutAt = 0;

// 2b. Globalne wylogowanie wszystkich stron
app.post("/api/auth/logout", (req, res) => {
    lastGlobalLogoutAt = Date.now();
    console.log("[AUTH] Globalne wylogowanie zrealizowane o: " + new Date(lastGlobalLogoutAt).toISOString());
    return res.json({ success: true, loggedOutAt: lastGlobalLogoutAt });
});

// 3. Weryfikacja tokenu (dla stron zewnętrznych: Carrd, HTML itp.)
app.get("/api/auth/verify", (req, res) => {
    let token = req.query.token;
    if (!token && req.headers.authorization) {
        const parts = req.headers.authorization.split(" ");
        if (parts.length === 2 && /^bearer$/i.test(parts[0])) {
            token = parts[1];
        }
    }

    if (!token) {
        return res.status(401).json({ valid: false, code: "NO_TOKEN", message: "Brak tokenu sesji." });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({
                valid: false,
                code: err.name === "TokenExpiredError" ? "EXPIRED" : "INVALID",
                message: err.message
            });
        }

        // Sprawdzenie czy nastąpiło globalne wylogowanie po wystawieniu tokenu
        if (decoded.issuedAt && decoded.issuedAt <= lastGlobalLogoutAt) {
            return res.status(401).json({
                valid: false,
                code: "LOGGED_OUT",
                message: "Sesja została unieważniona w Hubie (globalne wylogowanie)."
            });
        }

        return res.json({
            valid: true,
            role: decoded.role || "USER",
            expiresAt: decoded.exp * 1000
        });
    });
});

// 4. Dynamiczny skrypt klienta (/api/auth/client.js)
// Serwuje pełny widżet LKS Guard z cyberpunkowym interfejsem i weryfikacją Render Cloud
const EMBEDDED_CLIENT_TEMPLATE = "(function () {\n  \"use strict\";\n\n  var HUB_URL = \"%%HUB_URL%%\";\n  var SK = \"lks_vault_auth\";\n  var SDK = \"lks_vault_auth_date\";\n  var TOKEN_KEY = \"lks_render_auth_token\";\n  var ALLOWED_HASHES = [\"3cdf2dabfe18fb4d0e1f39fc86f836ed20ef0510d0f373b8071417906842bb93\"];\n\n  var d = document;\n  var $ = function (i) { return d.getElementById(i); };\n  function b() { return d.body || d.documentElement; }\n\n  if ($(\"L0\")) return;\n\n  // 1. Wstrzyknięcie czcionki i stylów LKS GUARD\n  (function injectStyles() {\n    if (d.getElementById(\"Z\")) return;\n\n    var fontLink = d.createElement(\"link\");\n    fontLink.rel = \"stylesheet\";\n    fontLink.href = \"https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&display=swap\";\n    (d.head || d.documentElement).appendChild(fontLink);\n\n    var css = `\n:root {\n    --shadow-drop: rgba(32, 32, 32, 0.4) 0px 0px 0px 2px, rgba(0, 0, 0, 0.65) 0px 4px 6px -1px, rgba(255, 255, 255, 0.08) 0px 1px 0px inset;\n    --shadow-inset: inset 0px 0px 0px 2px rgba(32, 32, 32, 0.4), inset 0px 4px 6px -1px rgba(0, 0, 0, 0.65), inset 0px 1px 0px rgba(255, 255, 255, 0.08);\n    --shadow-hover: rgba(32, 32, 32, 0.2) 0px 0px 0px 1px, rgba(0, 0, 0, 0.325) 0px 2px 3px -0.5px, rgba(255, 255, 255, 0.04) 0px 0.5px 0px inset;\n    --padding: 0.125rem;\n    --gap: 0.125rem;\n    --bg-tertiary: #2e2e2e;\n    --border-color: #2a2a2a;\n    --panel-bg: #2a2a2a;\n    --card-bg: #1e1e1e;\n    --text-muted: #858585;\n    --text-color: #e0e0e0;\n    --highlight-color: #f36c00;\n    --accent-ok: #09b83e;\n    --border-color-hover: #444444;\n    --hover-bg: #3c3c3c;\n    --font-family: \"JetBrains Mono\", monaco, courier, monospace;\n    --font-main: var(--font-family);\n    --transition-speed: 0.2s;\n    --transition-ease: ease;\n    --transition-ui: background-color var(--transition-speed) var(--transition-ease),\n        color var(--transition-speed) var(--transition-ease),\n        border-color var(--transition-speed) var(--transition-ease),\n        box-shadow var(--transition-speed) var(--transition-ease);\n}\n\n#L0, #L0 *, #L0 *::before, #L0 *::after {\n    border-radius: 0 !important;\n    box-sizing: border-box;\n}\n\nbody * {\n    visibility: hidden !important;\n}\n\n#L0, #L0 * {\n    visibility: visible !important;\n}\n\nbody.lks-guard-passed * {\n    visibility: visible !important;\n}\n\n#L0 {\n    position: fixed;\n    inset: 0;\n    z-index: 2147483647;\n    display: flex;\n    align-items: center;\n    justify-content: center;\n    background-color: var(--card-bg);\n    background-image:\n        linear-gradient(rgba(255, 255, 255, 0.025) 1px, transparent 1px),\n        linear-gradient(90deg, rgba(255, 255, 255, 0.025) 1px, transparent 1px),\n        linear-gradient(rgba(18, 18, 18, 0.76), rgba(18, 18, 18, 0.62)),\n        url('https://raw.githubusercontent.com/s-pro-v/os_pro/refs/heads/main/assets/images/bg4.jpg');\n    background-size: 24px 24px, 24px 24px, cover, cover;\n    background-position: center;\n    font-family: var(--font-family);\n    user-select: none;\n    -webkit-user-select: none;\n    transition: opacity 0.3s ease, visibility 0.3s ease;\n}\n\n#L0.d, #L0.d * {\n    opacity: 0;\n    visibility: hidden !important;\n    pointer-events: none;\n}\n\n#L0 .btn-bg {\n    display: flex;\n    justify-content: center;\n    align-items: center;\n    box-shadow: var(--shadow-inset);\n    padding: var(--padding);\n    gap: var(--gap);\n    position: relative;\n    overflow: hidden;\n    width: fit-content;\n    border: 1px solid var(--border-color);\n    background: var(--card-bg);\n    transition: var(--transition-ui);\n}\n\n#L0 .btn-bg:hover {\n    border: 1px solid var(--border-color-hover);\n}\n\n#L0 .btn {\n    box-shadow: var(--shadow-drop);\n    border: 1px solid var(--border-color);\n    background: var(--bg-tertiary);\n    color: var(--text-muted);\n    width: 100px;\n    height: 30px;\n    transition: var(--transition-ui);\n    font-family: var(--font-family);\n    font-weight: 700;\n    display: flex;\n    align-items: center;\n    margin: 0;\n}\n\n#L0 .btn:hover {\n    background: var(--hover-bg);\n    color: var(--text-color);\n    border: 1px solid var(--border-color-hover);\n    box-shadow: var(--shadow-hover);\n}\n\n#L0 .btn:active {\n    box-shadow: var(--shadow-inset);\n    background: var(--panel-bg);\n    color: var(--text-muted);\n    border: 1px solid var(--border-color);\n}\n\n#L0 .lks-outer-frame {\n    padding: 0.125rem;\n    background: #181818;\n    border: 1px solid var(--border-color);\n}\n\n#L0 .lks-outer-frame::before,\n#L0 .lks-outer-frame::after {\n    content: \"\";\n    position: absolute;\n    width: 10px;\n    height: 10px;\n    border: 1px solid var(--highlight-color);\n    pointer-events: none;\n    z-index: 3;\n    opacity: 0.75;\n}\n\n#L0 .lks-outer-frame::before {\n    top: 2px;\n    left: 2px;\n    border-right: none;\n    border-bottom: none;\n}\n\n#L0 .lks-outer-frame::after {\n    bottom: 2px;\n    right: 2px;\n    border-left: none;\n    border-top: none;\n}\n\n#L0 #L1.lks-chassis {\n    display: flex;\n    flex-direction: column;\n    align-items: stretch;\n    width: 390px;\n    max-width: 92vw;\n    height: auto;\n    padding: 0.375rem;\n    gap: 0.125rem;\n    background-color: var(--panel-bg);\n    background-image:\n        linear-gradient(rgba(255, 255, 255, 0.018) 1px, transparent 1px),\n        linear-gradient(90deg, rgba(255, 255, 255, 0.018) 1px, transparent 1px);\n    background-size: 12px 12px;\n    border: 1px solid var(--border-color);\n    text-transform: uppercase;\n}\n\n#L0 #L1.lks-chassis:hover {\n    background-color: var(--panel-bg);\n    border: 1px solid var(--border-color-hover);\n}\n\n#L0 .lks-row {\n    display: flex;\n    width: 100%;\n    gap: var(--gap);\n}\n\n#L0 .lks-grow {\n    flex: 1;\n    width: 40%;\n    height: fit-content;\n}\n\n#L0 .lks-full {\n    width: 100%;\n}\n\n#L0 .lks-led-box {\n    width: 28px;\n    height: 26px;\n    justify-content: center;\n    background: var(--card-bg);\n}\n\n#L0 #L-led {\n    display: block;\n    width: 6px;\n    height: 6px;\n    background: var(--highlight-color);\n    box-shadow: 0 0 6px var(--highlight-color);\n}\n\n#L0 .lks-telemetry {\n    width: 100%;\n    height: 26px;\n    padding: 0 0.5rem;\n    justify-content: space-between;\n    font-size: 10px;\n    letter-spacing: 0.06rem;\n    background: var(--card-bg);\n}\n\n#L0 .t-ok {\n    color: var(--highlight-color);\n    font-weight: 800;\n}\n\n#L0 .t-ses {\n    color: var(--text-color);\n    opacity: 0.85;\n}\n\n#L0 .t-clock {\n    color: var(--highlight-color);\n    font-weight: 700;\n}\n\n#L0 .lks-tile {\n    width: 100%;\n    height: 54px;\n    padding: 0 0.5rem 0 0.75rem;\n    justify-content: space-between;\n    background: linear-gradient(180deg, #323232 0%, #262626 100%);\n    border: 1px solid var(--border-color);\n}\n\n#L0 .lks-tile:hover {\n    background: linear-gradient(180deg, #3a3a3a 0%, #2c2c2c 100%);\n    border: 1px solid var(--border-color-hover);\n}\n\n#L0 .lks-tile-info {\n    display: flex;\n    flex-direction: column;\n    justify-content: center;\n    gap: 0.125rem;\n    text-align: left;\n}\n\n#L0 #L2 {\n    margin: 0;\n    font-size: 13px;\n    font-weight: 800;\n    letter-spacing: 0.08rem;\n    color: var(--text-color);\n    line-height: 1;\n}\n\n#L0 .lks-sub {\n    font-size: 9px;\n    font-weight: 700;\n    letter-spacing: 0.06rem;\n    color: var(--text-muted);\n    opacity: 0.65;\n    line-height: 1;\n}\n\n#L0 .lks-icon-slot {\n    padding: var(--padding);\n    background: var(--card-bg);\n}\n\n#L0 #L2-badge.lks-icon-btn {\n    width: 32px;\n    height: 32px;\n    justify-content: center;\n    background: var(--bg-tertiary);\n    color: var(--highlight-color);\n    border: 1px solid var(--border-color);\n}\n\n#L0 #L2-badge.lks-icon-btn:hover {\n    border: 1px solid var(--border-color-hover);\n    color: var(--text-color);\n}\n\n#L0 #L3.lks-msg {\n    width: 100%;\n    height: 30px;\n    padding: 0 0.625rem;\n    font-size: 10px;\n    letter-spacing: 0.1rem;\n    color: var(--text-muted);\n    justify-content: flex-start;\n}\n\n#L0 #L3.lks-msg::before {\n    content: \"SYS_MSG // \";\n    color: var(--highlight-color);\n    opacity: 0.75;\n    margin-right: 0.35rem;\n}\n\n/* MATRYCA KWADRACIKÓW SKANERA */\n#L0 .lks-row.L {\n    justify-content: space-between;\n    gap: 0.125rem;\n}\n\n#L0 .L .btn-bg {\n    flex: 1;\n    padding: 0.125rem;\n    aspect-ratio: 1 / 1;\n    max-width: 15px;\n}\n\n#L0 .L b.btn {\n    width: 100%;\n    height: 100%;\n    min-width: 6px;\n    min-height: 6px;\n    aspect-ratio: 1 / 1;\n    background: var(--bg-tertiary);\n    border: 1px solid var(--border-color);\n    animation: lks-scan 1.2s infinite steps(1);\n}\n\n#L0 .L b.btn:hover {\n    border: 1px solid var(--border-color-hover);\n}\n\n#L0 .L .btn-bg:nth-child(6n+1) b.btn { animation-delay: 0s; }\n#L0 .L .btn-bg:nth-child(6n+2) b.btn { animation-delay: 0.15s; }\n#L0 .L .btn-bg:nth-child(6n+3) b.btn { animation-delay: 0.3s; }\n#L0 .L .btn-bg:nth-child(6n+4) b.btn { animation-delay: 0.45s; }\n#L0 .L .btn-bg:nth-child(6n+5) b.btn { animation-delay: 0.6s; }\n#L0 .L .btn-bg:nth-child(6n+6) b.btn { animation-delay: 0.75s; }\n\n@keyframes lks-scan {\n    0%, 100% {\n        background: var(--bg-tertiary);\n        border-color: var(--border-color);\n    }\n    50% {\n        background: var(--highlight-color);\n        border-color: var(--border-color-hover);\n    }\n}\n\n#L0 #L4.lks-bar-slot {\n    width: 100%;\n    height: 15px;\n    padding: var(--padding);\n    background: var(--card-bg);\n    box-shadow: var(--shadow-inset);\n    border: 1px solid var(--border-color);\n    overflow: hidden;\n}\n\n#L0 #L4.lks-bar-slot:hover {\n    border: 1px solid var(--border-color-hover);\n}\n\n#L0 #L5.btn {\n    width: 0%;\n    height: 100%;\n    background: var(--highlight-color);\n    border: 1px solid var(--border-color);\n    box-shadow: var(--shadow-drop);\n}\n\n#L0 #L5.btn:hover {\n    border: 1px solid var(--border-color-hover);\n}\n\n#L0 #L6.lks-pct {\n    width: 58px;\n    height: 15px;\n    justify-content: center;\n    font-size: 10px;\n    letter-spacing: 0.06rem;\n    color: var(--highlight-color);\n}\n\n#L0 #L1.ok #L-led {\n    background: var(--accent-ok);\n    box-shadow: 0 0 6px var(--accent-ok);\n}\n\n#L0 #L1.ok .t-ok,\n#L0 #L1.ok .t-ses {\n    color: var(--accent-ok);\n}\n\n#L0 #L1.ok #L2-badge.lks-icon-btn {\n    color: var(--accent-ok);\n    border-color: var(--border-color);\n}\n\n#L0 #L1.ok #L2-badge.lks-icon-btn:hover {\n    border-color: var(--border-color-hover);\n}\n\n#L0 #L1.ok #L3,\n#L0 #L1.ok #L3::before {\n    color: var(--accent-ok);\n}\n\n#L0 #L1.ok #L3:empty::after {\n    content: \"ACCESS_GRANTED // SESJA AKTYWNA\";\n    color: var(--accent-ok);\n}\n\n#L0 #L1.ok #L5.btn {\n    background: var(--accent-ok);\n    border-color: var(--border-color);\n    animation: lks-load 1.65s linear forwards;\n}\n\n#L0 #L1.ok .L b.btn {\n    background: var(--accent-ok);\n    border-color: var(--border-color);\n    animation-timing-function: steps(2, end);\n    animation-iteration-count: infinite;\n}\n\n#L0 #L1.ok .L .btn-bg:nth-child(3n+1) b.btn { animation-name: srv-a; animation-duration: 0.55s; animation-delay: -0.18s; }\n#L0 #L1.ok .L .btn-bg:nth-child(3n+2) b.btn { animation-name: srv-b; animation-duration: 0.85s; animation-delay: -0.54s; }\n#L0 #L1.ok .L .btn-bg:nth-child(3n+3) b.btn { animation-name: srv-c; animation-duration: 0.68s; animation-delay: -0.31s; }\n\n#L0 #L1.er #L-led {\n    background: var(--highlight-color);\n    box-shadow: 0 0 8px var(--highlight-color);\n}\n\n#L0 #L1.er .t-ok,\n#L0 #L1.er .t-ses,\n#L0 #L1.er #L2,\n#L0 #L1.er #L3,\n#L0 #L1.er #L2-badge {\n    color: var(--highlight-color);\n}\n\n#L0 #L1.er #L3::before {\n    content: \"ERR_CODE // \";\n}\n\n#L0 #L1.er .L b.btn {\n    background: var(--highlight-color);\n    border-color: var(--border-color);\n    opacity: 0.45;\n}\n\n#L0 #L1.er #L5.btn {\n    width: 100%;\n    background: var(--highlight-color);\n    border-color: var(--border-color);\n}\n\n@keyframes lks-load {\n    0% { width: 0%; }\n    25% { width: 25%; }\n    31% { width: 25%; }\n    65% { width: 65%; }\n    80% { width: 65%; }\n    100% { width: 100%; }\n}\n\n@keyframes srv-a {\n    0%, 100% { opacity: 0.25; }\n    50% { opacity: 1; }\n}\n@keyframes srv-b {\n    0%, 100% { opacity: 0.45; }\n    58% { opacity: 1; }\n}\n@keyframes srv-c {\n    0%, 100% { opacity: 0.15; }\n    68% { opacity: 1; }\n}\n`;\n    var s = d.createElement(\"style\");\n    s.id = \"Z\";\n    s.textContent = css;\n    (d.head || d.documentElement).appendChild(s);\n  })();\n\n  var ICON_LOCK = '<svg viewBox=\"0 0 24 24\" width=\"15\" height=\"15\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"4\" y=\"11\" width=\"16\" height=\"10\"/><path d=\"M8 11V7a4 4 0 0 1 8 0v4\"/></svg>';\n  var ICON_OK = '<svg viewBox=\"0 0 24 24\" width=\"15\" height=\"15\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.2\"><path d=\"M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3z\"/><path d=\"M9 12l2 2 4-4\"/></svg>';\n  var ICON_ERR = '<svg viewBox=\"0 0 24 24\" width=\"15\" height=\"15\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.2\"><path d=\"M12 2L2 20h20L12 2z\"/><path d=\"M12 9v5\"/><path d=\"M12 16h.01\"/></svg>';\n\n  function clearSess() {\n    try {\n      sessionStorage.removeItem(SK);\n      sessionStorage.removeItem(SDK);\n      localStorage.removeItem(SK);\n      localStorage.removeItem(SDK);\n      localStorage.removeItem(TOKEN_KEY);\n    } catch (e) {}\n  }\n\n  function sessOk() {\n    var t = new Date().toDateString(),\n      x = sessionStorage.getItem(SK) || localStorage.getItem(SK),\n      y = sessionStorage.getItem(SDK) || localStorage.getItem(SDK);\n    if (x === \"VALID\" && y !== t) {\n      clearSess();\n      return 0;\n    }\n    return x === \"VALID\" && y === t;\n  }\n\n  function pad(n) { return (n < 10 ? \"0\" : \"\") + n; }\n\n  function updateNavStatus(state, label, status) {\n    var codeEl = $(\"L-st-code\"), lblEl = $(\"L-st-lbl\");\n    if (codeEl && label) codeEl.textContent = label;\n    if (lblEl && status) lblEl.textContent = status;\n\n    var n = $(\"lks-nav-status\");\n    if (!n) return;\n    n.setAttribute(\"data-lks-state\", state || \"wait\");\n    n.setAttribute(\"title\", \"LKS_SECURE_HUB // CORE_V5.0 [RENDER_CLOUD]\");\n    n.style.cursor = \"pointer\";\n\n    if (n.tagName === \"A\") {\n      n.href = HUB_URL || \"https://guard-7948.onrender.com/\";\n      n.target = \"_blank\";\n      n.rel = \"noopener noreferrer\";\n    } else if (!n.dataset.boundClick) {\n      n.dataset.boundClick = \"1\";\n      n.addEventListener(\"click\", function (e) {\n        e.preventDefault();\n        window.open(HUB_URL || \"https://guard-7948.onrender.com/\", \"_blank\");\n      });\n    }\n\n    var l = n.querySelector(\".nav-pill__lks-label\"),\n      s = n.querySelector(\".nav-pill__lks-status\");\n    if (l) l.textContent = label || \"CORE_V5.0\";\n    if (s && status) s.textContent = status;\n  }\n\n  var clockId = 0;\n  function startNavClock() {\n    if (clockId) return;\n    function tick() {\n      var t = new Date(),\n        dateStr = pad(t.getDate()) + \".\" + pad(t.getMonth() + 1) + \".\" + t.getFullYear(),\n        timeStr = pad(t.getHours()) + \":\" + pad(t.getMinutes()) + \":\" + pad(t.getSeconds()),\n        mDate = $(\"L-date\"),\n        mTime = $(\"L-time\"),\n        dd = $(\"lks-nav-date\"),\n        tt = $(\"lks-nav-time\");\n      if (mDate) mDate.textContent = dateStr;\n      if (mTime) mTime.textContent = timeStr;\n      if (dd) dd.textContent = dateStr;\n      if (tt) {\n        tt.textContent = timeStr;\n        tt.setAttribute(\"datetime\", t.toISOString());\n      }\n    }\n    tick();\n    clockId = setInterval(tick, 1000);\n  }\n\n  function setSt(x, w) {\n    var p = $(\"L1\"), a = $(\"L2\"), bg = $(\"L2-badge\"), s = $(\"L3\");\n    if (p) p.classList.remove(\"er\");\n    if (w) {\n      if (p) p.classList.add(\"ok\");\n      if (a) a.textContent = \"GUARD // OK\";\n      if (bg) bg.innerHTML = ICON_OK;\n      if (s) s.textContent = x || \"\";\n      updateNavStatus(\"ok\", \"OK\", \"SESJA\");\n    } else if (s && x) s.textContent = x;\n  }\n\n  function hide() {\n    var e = b();\n    e.classList.add(\"lks-guard-passed\");\n    e.classList.remove(\"lks-page-loading\");\n    var o = $(\"L0\");\n    if (o) o.classList.add(\"d\");\n  }\n\n  function redir(e) {\n    clearSess();\n    var o = $(\"L0\"), p = $(\"L1\"), a = $(\"L2\"), bg = $(\"L2-badge\"), s = $(\"L3\");\n    if (o) {\n      b().classList.remove(\"lks-guard-passed\");\n      b().classList.add(\"lks-page-loading\");\n      o.classList.remove(\"d\");\n    }\n    updateNavStatus(\"stop\", \"STOP\", e ? \"SESJA\" : \"BRAK\");\n    if (p) { p.classList.remove(\"ok\"); p.classList.add(\"er\"); }\n    if (a) a.textContent = \"GUARD // STOP\";\n    if (bg) bg.innerHTML = ICON_ERR;\n    if (s) s.textContent = e ? \"Sesja wygasła → Hub\" : \"Brak autoryzacji → Hub\";\n    var g = HUB_URL || location.origin + \"/\",\n      u = location.origin + location.pathname;\n    setTimeout(function () {\n      var sep = g.indexOf(\"?\") >= 0 ? \"&\" : \"?\";\n      location.replace(g + sep + \"return_url=\" + encodeURIComponent(u));\n    }, 1000);\n  }\n\n  var isCheckingSession = false;\n  async function checkServerSession() {\n    if (isCheckingSession) return;\n    var token = localStorage.getItem(TOKEN_KEY);\n    if (!token) {\n      if (!sessOk()) redir(1);\n      return;\n    }\n    isCheckingSession = true;\n    try {\n      var vUrl = HUB_URL.replace(/\\/$/, \"\") + \"/api/auth/verify?token=\" + encodeURIComponent(token);\n      var r = await fetch(vUrl, { method: \"GET\", headers: { \"Accept\": \"application/json\" } });\n      if (!r.ok) {\n        clearSess();\n        redir(1);\n        return;\n      }\n      var data = await r.json();\n      if (!data || !data.valid) {\n        clearSess();\n        redir(1);\n        return;\n      }\n    } catch (err) {\n      if (!sessOk()) {\n        clearSess();\n        redir(1);\n      }\n    } finally {\n      isCheckingSession = false;\n    }\n  }\n\n  function watch() {\n    function k() {\n      if (!d.hidden) {\n        if (!sessOk()) redir(1);\n        checkServerSession();\n      }\n      checkHubSession();\n    }\n    setInterval(k, 2000);\n    d.addEventListener(\"visibilitychange\", function () {\n      if (!d.hidden) {\n        if (!sessOk()) redir(1);\n        checkServerSession();\n      }\n    });\n    window.addEventListener(\"focus\", function () {\n      if (!sessOk()) redir(1);\n      checkServerSession();\n    });\n  }\n\n  function go() {\n    setSt(\"\", 1);\n    var bar = $(\"L5\"), pct = $(\"L6\"), done = 0;\n    function finish() {\n      if (done) return;\n      done = 1;\n      if (pct) pct.textContent = \"100%\";\n      hide();\n      updateNavStatus(\"ok\", \"OK\", \"SESJA\");\n      startNavClock();\n      watch();\n    }\n    function showProgress(start) {\n      var elapsed = Math.min((performance.now() - start) / 2650, 1), value;\n      if (elapsed < 0.25) value = elapsed * 100;\n      else if (elapsed < 0.31) value = 25;\n      else if (elapsed < 0.65) value = 25 + ((elapsed - 0.31) / 0.34) * 40;\n      else if (elapsed < 0.8) value = 65;\n      else value = 65 + ((elapsed - 0.8) / 0.2) * 35;\n      if (pct) pct.textContent = Math.min(100, Math.round(value)) + \"%\";\n      if (!done && elapsed < 1) requestAnimationFrame(function () { showProgress(start); });\n    }\n    showProgress(performance.now());\n    if (bar) bar.addEventListener(\"animationend\", finish, { once: true });\n    setTimeout(finish, bar ? 3200 : 0);\n  }\n\n  async function sha256(t) {\n    if (!t) return \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\";\n    if (window.crypto && crypto.subtle && crypto.subtle.digest) {\n      var buf = await crypto.subtle.digest(\"SHA-256\", new TextEncoder().encode(t));\n      return Array.from(new Uint8Array(buf)).map(function (x) { return x.toString(16).padStart(2, \"0\"); }).join(\"\");\n    }\n    return \"\";\n  }\n\n  function checkHubSession() {\n    if (window.opener && !window.opener.closed) {\n      try { window.opener.postMessage({ type: \"LKS_SESSION_CHECK\" }, \"*\"); } catch (e) {}\n    }\n  }\n\n  window.addEventListener(\"message\", function (e) {\n    if (!e.data || typeof e.data !== \"object\") return;\n    if (e.data.type === \"LKS_GUARD_LOGOUT\" || (e.data.type === \"LKS_SESSION_STATUS\" && e.data.valid === false)) {\n      clearSess();\n      redir(1);\n    }\n  });\n\n  window.addEventListener(\"storage\", function (e) {\n    if ((e.key === SK && e.newValue !== \"VALID\") || e.key === \"lks_vault_logout_signal\") {\n      clearSess();\n      redir(1);\n    }\n  });\n\n  try {\n    var bc = new BroadcastChannel(\"lks_channel\");\n    bc.onmessage = function (e) {\n      if (e.data && (e.data.type === \"LKS_GUARD_LOGOUT\" || e.data.valid === false)) {\n        clearSess();\n        redir(1);\n      }\n    };\n  } catch (e) {}\n\n  if (window.opener && !window.opener.closed) {\n    try { window.opener.postMessage({ type: \"LKS_REGISTER_CLIENT\" }, \"*\"); } catch (e) {}\n  }\n  window.addEventListener(\"focus\", checkHubSession);\n\n  async function run() {\n    var q = new URLSearchParams(location.search);\n    if (q.get(\"lks_logout\") === \"1\") {\n      clearSess();\n      history.replaceState({}, d.title, location.origin + location.pathname);\n      location.replace(HUB_URL || location.origin + \"/\");\n      return;\n    }\n\n    var n = q.get(\"auth\");\n    var day = new Date().getDate();\n\n    // 1. Sprawdzenie tokenu z parametru URL\n    if (n) {\n      try {\n        var verifyUrl = HUB_URL.replace(/\\/$/, \"\") + \"/api/auth/verify?token=\" + encodeURIComponent(n);\n        var res = await fetch(verifyUrl, { method: \"GET\", headers: { \"Accept\": \"application/json\" } });\n        if (res.ok) {\n          var data = await res.json();\n          if (data && data.valid) {\n            sessionStorage.setItem(SK, \"VALID\");\n            sessionStorage.setItem(SDK, new Date().toDateString());\n            localStorage.setItem(TOKEN_KEY, n);\n            history.replaceState({}, d.title, location.origin + location.pathname);\n            go();\n            checkHubSession();\n            return;\n          }\n        }\n      } catch (err) {}\n\n      // Fallback SHA-256\n      for (var i = 0; i < ALLOWED_HASHES.length; i++) {\n        var exp = await sha256(ALLOWED_HASHES[i] + \"_\" + day);\n        if (n.toLowerCase() === exp.toLowerCase()) {\n          sessionStorage.setItem(SK, \"VALID\");\n          sessionStorage.setItem(SDK, new Date().toDateString());\n          history.replaceState({}, d.title, location.origin + location.pathname);\n          go();\n          checkHubSession();\n          return;\n        }\n      }\n      clearSess();\n      redir(0);\n      return;\n    }\n\n    // 2. Sprawdzenie tokenu w pamięci podręcznej (Render JWT)\n    var savedToken = localStorage.getItem(TOKEN_KEY);\n    if (savedToken) {\n      try {\n        var vUrl = HUB_URL.replace(/\\/$/, \"\") + \"/api/auth/verify?token=\" + encodeURIComponent(savedToken);\n        var vRes = await fetch(vUrl, { method: \"GET\", headers: { \"Accept\": \"application/json\" } });\n        if (vRes.ok) {\n          var vData = await vRes.json();\n          if (vData && vData.valid) {\n            sessionStorage.setItem(SK, \"VALID\");\n            sessionStorage.setItem(SDK, new Date().toDateString());\n            go();\n            return;\n          }\n        }\n      } catch (e) {}\n    }\n\n    if (window.opener && !window.opener.closed) {\n      checkHubSession();\n      if (sessOk()) { go(); return; }\n      redir(0);\n      return;\n    }\n\n    if (sessOk()) { go(); return; }\n\n    // Dopuszczalność podglądu w środowisku czysto lokalnym\n    if (location.protocol === \"file:\" || location.hostname === \"localhost\" || location.hostname === \"127.0.0.1\") {\n      go();\n      return;\n    }\n\n    clearSess();\n    redir(0);\n  }\n\n  function mount() {\n    try { build(); } catch (e) { hide(); throw e; }\n  }\n\n  function build() {\n    var e = b();\n    e.classList.add(\"lks-page-loading\");\n\n    var leds = \"\";\n    for (var k = 0; k < 24; k++) {\n      leds += '<div class=\"btn-bg\"><b class=\"btn\"></b></div>';\n    }\n\n    var o = d.createElement(\"div\");\n    o.id = \"L0\";\n    o.innerHTML =\n      '<div class=\"btn-bg lks-outer-frame\">' +\n        '<div id=\"L1\" class=\"btn lks-chassis\">' +\n          '<div class=\"lks-row lks-top-bar\">' +\n            '<div class=\"btn-bg\"><div class=\"btn lks-led-box\"><i id=\"L-led\"></i></div></div>' +\n            '<div class=\"btn-bg lks-grow\">' +\n              '<div class=\"btn lks-telemetry\">' +\n                '<span id=\"L-st-code\" class=\"t-ok\">WAIT</span>' +\n                '<span id=\"L-st-lbl\" class=\"t-ses\">SESJA</span>' +\n                '<span id=\"L-date\" class=\"t-clock\">--.--.----</span>' +\n                '<span id=\"L-time\" class=\"t-clock\">--:--:--</span>' +\n              '</div>' +\n            '</div>' +\n          '</div>' +\n          '<div class=\"btn-bg lks-full\">' +\n            '<div class=\"btn lks-tile\">' +\n              '<div class=\"lks-tile-info\">' +\n                '<p id=\"L2\">LKS_GUARD</p>' +\n                '<span class=\"lks-sub\">SECURITY GATE // RENDER CLOUD</span>' +\n              '</div>' +\n              '<div class=\"btn-bg lks-icon-slot\">' +\n                '<span id=\"L2-badge\" class=\"btn lks-icon-btn\">' + ICON_LOCK + '</span>' +\n              '</div>' +\n            '</div>' +\n          '</div>' +\n          '<div class=\"btn-bg lks-full\"><p id=\"L3\" class=\"btn lks-msg\">Weryfikacja sesji…</p></div>' +\n          '<div class=\"lks-row L\">' + leds + '</div>' +\n          '<div class=\"lks-row\">' +\n            '<div class=\"btn-bg lks-grow\"><div id=\"L4\" class=\"btn lks-bar-slot\"><div id=\"L5\" class=\"btn\"></div></div></div>' +\n            '<div class=\"btn-bg\"><div id=\"L6\" class=\"btn lks-pct\">0%</div></div>' +\n          '</div>' +\n        '</div>' +\n      '</div>';\n    e.appendChild(o);\n    startNavClock();\n    run();\n  }\n\n  if (d.readyState === \"loading\") d.addEventListener(\"DOMContentLoaded\", mount);\n  else mount();\n})();\n\n";

app.get("/api/auth/client.js", (req, res) => {
    const hubUrl = getServerUrl(req);
    let script = "";
    try {
        const templatePath = path.join(__dirname, "assets", "client-template.js");
        if (fs.existsSync(templatePath)) {
            script = fs.readFileSync(templatePath, "utf8");
        }
    } catch (e) {}
    if (!script) script = EMBEDDED_CLIENT_TEMPLATE;
    const finalScript = script.replace(/%%HUB_URL%%/g, hubUrl);
    res.setHeader("Content-Type", "application/javascript; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    res.send(finalScript);
});

// 5. Obsługa plików statycznych interfejsu (index.html, index.css, index.js, assets, favicon)
app.use(express.static(path.join(__dirname), {
    index: "index.html",
    extensions: ["html", "htm"]
}));

// Fallback do index.html dla SPA
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
    console.log(`===============================================`);
    console.log(`🚀 LKS GUARD (RENDER EDITION) ONLINE`);
    console.log(`📡 Port: ${PORT}`);
    console.log(`🔑 Master Key Configured: ${MASTER_KEY ? "YES" : "NO"}`);
    console.log(`🔒 JWT Token Expiry: ${TOKEN_EXPIRES_IN}`);
    console.log(`🌐 Healthcheck: http://localhost:${PORT}/healthz`);
    console.log(`===============================================`);
});
