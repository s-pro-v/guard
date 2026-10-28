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

        return res.json({
            valid: true,
            role: decoded.role || "USER",
            expiresAt: decoded.exp * 1000
        });
    });
});

// 4. Dynamiczny skrypt klienta (/api/auth/client.js)
// Serwuje pełny widżet LKS Guard z cyberpunkowym interfejsem i weryfikacją Render Cloud
let clientTemplateCache = "";
try {
    const templatePath = path.join(__dirname, "assets", "client-template.js");
    if (fs.existsSync(templatePath)) {
        clientTemplateCache = fs.readFileSync(templatePath, "utf8");
    }
} catch (e) {
    console.warn("Could not cache client-template.js:", e.message);
}

app.get("/api/auth/client.js", (req, res) => {
    const hubUrl = getServerUrl(req);
    let script = clientTemplateCache;
    if (!script) {
        try {
            const templatePath = path.join(__dirname, "assets", "client-template.js");
            script = fs.readFileSync(templatePath, "utf8");
        } catch (e) {}
    }
    const finalScript = script ? script.replace(/%%HUB_URL%%/g, hubUrl) : "// Error loading client template";

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
