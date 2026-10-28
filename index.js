"use strict";

const CONFIG = {
    // Rejestr dozwolonych skrótów SHA-256 (Zero-Plaintext)
    ALLOWED_HASHES: {
        "3cdf2dabfe18fb4d0e1f39fc86f836ed20ef0510d0f373b8071417906842bb93": "ROOT_SYS"
    },
    DEFAULT_TARGET_HASH: "3cdf2dabfe18fb4d0e1f39fc86f836ed20ef0510d0f373b8071417906842bb93",
    SESSION_KEY: "lks_vault_auth",
    SESSION_DATE_KEY: "lks_vault_auth_date",
    SESSION_HASH_KEY: "lks_vault_auth_hash",
    CARDS_URL: "https://raw.githubusercontent.com/s-pro-v/json-lista/refs/heads/main/card.json",
    LOGOUT_PARAM: "lks_logout=1",
    RETURN_URL_KEY: "lks_return_url",
    THEME_KEY: "lks_theme"
};

(function applyStoredTheme() {
    try {
        var t = localStorage.getItem(CONFIG.THEME_KEY);
        if (t === "light" || t === "dark") {
            document.documentElement.setAttribute("theme", t);
        } else {
            document.documentElement.setAttribute("theme", "dark");
        }
    } catch (e) {
        document.documentElement.setAttribute("theme", "dark");
    }
})();

async function computeSha256(text) {
    if (!text) return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    if (window.crypto && crypto.subtle && crypto.subtle.digest) {
        try {
            const buffer = new TextEncoder().encode(text);
            const hashBuf = await crypto.subtle.digest("SHA-256", buffer);
            return Array.from(new Uint8Array(hashBuf))
                .map(b => b.toString(16).padStart(2, "0"))
                .join("");
        } catch (e) { }
    }
    // Awaryjna implementacja SHA-256 dla środowisk bez Web Crypto
    function rrot(v, a) { return (v >>> a) | (v << (32 - a)); }
    const m = Math.pow, maxW = m(2, 32), words = [], aLen = text.length * 8, hash = [], k = [];
    let p = 0; const comp = {};
    for (let cand = 2; p < 64; cand++) {
        if (!comp[cand]) {
            for (let i = 0; i < 313; i += cand) comp[i] = cand;
            hash[p] = (m(cand, 0.5) * maxW) | 0;
            k[p++] = (m(cand, 1 / 3) * maxW) | 0;
        }
    }
    text += "\x80";
    while ((text.length % 64) - 56) text += "\x00";
    for (let i = 0; i < text.length; i++) words[i >> 2] |= text.charCodeAt(i) << (((3 - i) % 4) * 8);
    words[words.length] = (aLen / maxW) | 0;
    words[words.length] = aLen;
    for (let j = 0; j < words.length;) {
        const w = words.slice(j, (j += 16)), oH = hash.slice(0);
        hash.splice(0, 8);
        for (let i = 0; i < 64; i++) {
            const w15 = w[i - 15], w2 = w[i - 2], a = hash[0], e = hash[4];
            const t1 = hash[7] + (rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25)) + ((e & hash[5]) ^ (~e & hash[6])) + k[i] + (w[i] = i < 16 ? w[i] : (w[i - 16] + (rrot(w15, 7) ^ rrot(w15, 18) ^ (w15 >>> 3)) + w[i - 7] + (rrot(w2, 17) ^ rrot(w2, 19) ^ (w2 >>> 10))) | 0);
            const t2 = (rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22)) + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
            hash.unshift((t1 + t2) | 0);
            hash[4] = (hash[4] + t1) | 0;
        }
        for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oH[i]) | 0;
    }
    let res = "";
    for (let i = 0; i < 8; i++) {
        for (let i2 = 3; i2 >= 0; i2--) {
            const byte = (hash[i] >> (i2 * 8)) & 255;
            res += (byte < 16 ? "0" : "") + byte.toString(16);
        }
    }
    return res;
}

async function getShaAuthToken(hashKey) {
    const key = hashKey || localStorage.getItem(CONFIG.SESSION_HASH_KEY) || CONFIG.DEFAULT_TARGET_HASH;
    const day = new Date().getDate();
    // Oblicza skrót SHA-256(KEY_HASH + "_" + DAY)
    return await computeSha256(key + "_" + day);
}

const dom = {
    auth: document.getElementById('authView'),
    hub: document.getElementById('hubView'),
    mainView: document.getElementById('mainView'),
    phasePill: document.getElementById('phasePill'),
    input: document.getElementById('passInput'),
    terminal: document.getElementById('terminal'),
    lvl: document.getElementById('authLvl'),
    statusBarMode: document.getElementById('statusBarMode'),
    statusBarCenter: document.getElementById('statusBarCenter'),
    statusBarTheme: document.getElementById('statusBarTheme'),
    statusBarLed: document.getElementById('statusBarLed'),
    statusBarSession: document.getElementById('statusBarSession'),
    footSessionState: document.getElementById('footSessionState'),
    shaLive: document.getElementById('shaLivePreview'),
    returnBanner: document.getElementById('returnBanner'),
    returnUrlText: document.getElementById('returnUrlText')
};

let hubNodeCount = 0;
var pageLoadingDismissed = false;
var pageLoadingStartedAt = 0;
var PAGE_LOADING_MIN_MS = 2400;
var PAGE_LOADING_SAFETY_MS = 20000;

function pageLoadingNow() {
    return (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
}

function setPageLoadProgress(pct) {
    var overlay = document.getElementById("pageLoadingOverlay");
    if (!overlay || overlay.classList.contains("lks-page-load--done")) return;
    var p = Math.max(0, Math.min(100, Math.round(Number(pct))));
    var fill = document.getElementById("pageLoadBarFill");
    var bar = document.getElementById("pageLoadBar");
    var pctEl = document.getElementById("pageLoadBarPct");
    if (fill) fill.style.width = p + "%";
    if (bar) bar.setAttribute("aria-valuenow", String(p));
    if (pctEl) pctEl.textContent = p + "%";
}

function setPageLoadActivity(msg, pct) {
    var overlay = document.getElementById("pageLoadingOverlay");
    var el = document.getElementById("pageLoadActivity");
    if (!el || !overlay || overlay.classList.contains("lks-page-load--done")) return;
    el.textContent = msg;
    if (typeof pct === "number" && !isNaN(pct)) setPageLoadProgress(pct);
}

function syncPageLoadSessionLine() {
    var overlay = document.getElementById("pageLoadingOverlay");
    var el = document.getElementById("pageLoadSessionLine");
    if (!el || !overlay || overlay.classList.contains("lks-page-load--done")) return;
    var s = getSessionTokenState();
    el.classList.remove("lks-page-load__session--ok", "lks-page-load__session--bad");
    if (s.kind === "ok") {
        el.classList.add("lks-page-load__session--ok");
        el.textContent = "Sesja LKS jest aktualna (SHA-256) — możesz kontynuować po zakończeniu ładowania.";
    } else {
        el.classList.add("lks-page-load__session--bad");
        var bad = {
            expired: "Sesja dzienna wygasła — wymagana ponowna weryfikacja kluczem SHA-256.",
            none: "Brak aktywnej sesji — po załadowaniu wymagana weryfikacja kluczem SHA-256."
        };
        el.textContent = bad[s.kind] || bad.none;
    }
}

function dismissPageLoadingOverlay() {
    if (pageLoadingDismissed) return;
    pageLoadingDismissed = true;
    setPageLoadProgress(100);
    var el = document.getElementById("pageLoadingOverlay");
    if (el) {
        el.classList.add("lks-page-load--done");
        el.setAttribute("aria-busy", "false");
        el.setAttribute("aria-hidden", "true");
    }
    document.body.classList.remove("lks-page-loading");
    if (el) {
        setTimeout(function () {
            if (el.parentNode) el.parentNode.removeChild(el);
        }, 1100);
    }
}

function setAppPhase(phase) {
    var n = phase === 2 ? 2 : 1;
    if (dom.mainView) dom.mainView.setAttribute('data-phase', String(n));
    if (dom.phasePill) {
        dom.phasePill.textContent = n === 2 ? 'FAZA 2 · HUB' : 'FAZA 1 · DOSTĘP LKS';
        dom.phasePill.classList.toggle('lks-phase-pill--hub', n === 2);
        dom.phasePill.classList.toggle('lks-phase-pill--gate', n === 1);
    }
    refreshStatusBar();
}

function refreshStatusBar() {
    applySessionValidityToDom(getSessionTokenState());
    var theme = document.documentElement.getAttribute("theme") || "dark";
    if (dom.statusBarTheme) {
        dom.statusBarTheme.textContent = "MOTYW: " + (theme === "dark" ? "CIEMNY" : "JASNY");
    }
    var phase = dom.mainView ? (dom.mainView.getAttribute("data-phase") || "1") : "1";
    if (dom.statusBarMode) {
        dom.statusBarMode.textContent = phase === "2" ? "SESJA: HUB_AKTYWNY" : "SESJA: BRAMKA_LKS";
    }
    if (dom.statusBarCenter) {
        dom.statusBarCenter.textContent = phase === "2"
            ? ("WĘZŁY: " + hubNodeCount)
            : "OXY_OS · LKS_SECURE_HUB";
    }
    if (dom.statusBarLed) {
        dom.statusBarLed.classList.remove("lks-statusbar__led--hub", "lks-statusbar__led--denied");
        if (phase === "2") dom.statusBarLed.classList.add("lks-statusbar__led--hub");
    }
}

let uptimeSec = 0;

function isCurrentlyLoggedIn() {
    var stored = localStorage.getItem(CONFIG.SESSION_KEY);
    var storedDate = localStorage.getItem(CONFIG.SESSION_DATE_KEY);
    var today = new Date().toDateString();
    if (stored === "VALID" && storedDate !== today) {
        localStorage.removeItem(CONFIG.SESSION_KEY);
        localStorage.removeItem(CONFIG.SESSION_DATE_KEY);
        localStorage.removeItem(CONFIG.SESSION_HASH_KEY);
        return false;
    }
    return stored === "VALID" && storedDate === today;
}

function getSessionTokenState() {
    var stored = null;
    var storedDate = null;
    try {
        stored = localStorage.getItem(CONFIG.SESSION_KEY);
        storedDate = localStorage.getItem(CONFIG.SESSION_DATE_KEY);
    } catch (e) { }
    var today = new Date().toDateString();
    if (stored === "VALID" && storedDate === today) {
        return {
            kind: "ok",
            statusText: "SESJA_LKS: AKTUALNA (SHA-256)",
            footText: "AKTUALNA",
            title: "Sesja w przeglądarce jest aktywna na dziś. Token SHA-256 jest ważny."
        };
    }
    if (stored === "VALID" && storedDate && storedDate !== today) {
        return {
            kind: "expired",
            statusText: "SESJA_LKS: WYGASŁA",
            footText: "WYGASŁA",
            title: "Data zapisu nie jest dzisiejsza. Zaloguj się ponownie wektorem SHA-256."
        };
    }
    return {
        kind: "none",
        statusText: "SESJA_LKS: BRAK",
        footText: "BRAK",
        title: "Brak aktywnej sesji LKS."
    };
}

function applySessionValidityToDom(s) {
    var kinds = ["ok", "expired", "none"];
    if (dom.statusBarSession) {
        dom.statusBarSession.textContent = s.statusText;
        dom.statusBarSession.setAttribute("title", s.title);
        kinds.forEach(function (k) {
            dom.statusBarSession.classList.remove("lks-statusbar__session--" + k);
        });
        dom.statusBarSession.classList.add("lks-statusbar__session--" + s.kind);
    }
    if (dom.footSessionState) {
        dom.footSessionState.textContent = s.footText;
        dom.footSessionState.setAttribute("title", s.title);
        kinds.forEach(function (k) {
            dom.footSessionState.classList.remove("lks-footbar__session--" + k);
        });
        dom.footSessionState.classList.add("lks-footbar__session--" + s.kind);
    }
}

function addLog(msg, type = '') {
    if (!dom.terminal) return;
    const line = document.createElement('div');
    line.className = 'lks-log__line ' + type;
    const time = new Date().toISOString().split('T')[1].slice(0, -1);
    line.textContent = time + " :: " + msg;
    dom.terminal.appendChild(line);
    dom.terminal.scrollTop = dom.terminal.scrollHeight;
}

var pendingReturnUrl = null;

function clearReturnUrl() {
    pendingReturnUrl = null;
    try {
        sessionStorage.removeItem(CONFIG.RETURN_URL_KEY);
        localStorage.removeItem(CONFIG.RETURN_URL_KEY);
    } catch (e) { }

    var banner = document.getElementById("returnBanner");
    if (banner) banner.style.display = "none";

    var authSubmitBtn = document.getElementById("authBtn");
    if (authSubmitBtn) {
        authSubmitBtn.innerHTML = '<i data-lucide="key-round" class="lks-icon" aria-hidden="true"></i> AUTORYZUJ_SESJĘ (SHA-256)';
        if (window.lucide && typeof window.lucide.createIcons === "function") window.lucide.createIcons();
    }

    try {
        var u = new URL(window.location.href);
        if (u.searchParams.has("return_url") || u.searchParams.has("redirect") || u.searchParams.has("r")) {
            u.searchParams.delete("return_url");
            u.searchParams.delete("redirect");
            u.searchParams.delete("r");
            var cleanUrl = u.pathname + (u.search ? u.search : "") + u.hash;
            window.history.replaceState({}, document.title, cleanUrl);
        }
    } catch (e) { }
}

function receiveReturnUrl() {
    var params = new URLSearchParams(window.location.search);
    var rawUrl = params.get("return_url") || params.get("redirect") || params.get("r");

    if (rawUrl) {
        try {
            var parsed = new URL(rawUrl, window.location.href);
            if (parsed.protocol === "http:" || parsed.protocol === "https:") {
                pendingReturnUrl = parsed.href;
            } else {
                pendingReturnUrl = null;
            }
        } catch (e) {
            pendingReturnUrl = rawUrl;
        }
    } else {
        pendingReturnUrl = null;
        try {
            sessionStorage.removeItem(CONFIG.RETURN_URL_KEY);
            localStorage.removeItem(CONFIG.RETURN_URL_KEY);
        } catch (e) { }
    }

    if (pendingReturnUrl) {
        var banner = document.getElementById("returnBanner");
        var bannerText = document.getElementById("returnUrlText");
        if (banner && bannerText) {
            bannerText.textContent = pendingReturnUrl;
            banner.style.display = "flex";
        }

        var authSubmitBtn = document.getElementById("authBtn");
        if (authSubmitBtn) {
            authSubmitBtn.innerHTML = '<i data-lucide="corner-down-right" class="lks-icon" aria-hidden="true"></i> AUTORYZUJ I PRZEJDŹ DO STRONY';
            if (window.lucide && typeof window.lucide.createIcons === "function") window.lucide.createIcons();
        }

        var cancelBtn = document.getElementById("cancelReturnBtn");
        if (cancelBtn) {
            cancelBtn.onclick = function (e) {
                e.preventDefault();
                clearReturnUrl();
                addLog("RETURN_URL: Anulowano przekierowanie — pozostajesz w Hubie.", "warning");
            };
        }
    }
}

async function sendForwardToReturnUrl(hashUsed, serverToken) {
    var returnUrl = pendingReturnUrl;
    if (!returnUrl) return false;

    clearReturnUrl();

    addLog("REDIRECT: Przekierowanie do węzła: " + returnUrl, "success");
    var token = serverToken || localStorage.getItem("lks_render_auth_token") || await getShaAuthToken(hashUsed);
    var sep = returnUrl.indexOf("?") >= 0 ? "&" : "?";
    var target = returnUrl + sep + "auth=" + encodeURIComponent(token);

    setTimeout(function () {
        window.location.replace(target);
    }, 180);
    return true;
}

async function handleAuth() {
    var raw = (dom.input ? dom.input.value : "").trim();
    if (!raw) {
        addLog("ERR_AUTH: Proszę wprowadzić wektor inicjalizacyjny!", "danger");
        return;
    }

    var inputHash = await computeSha256(raw);
    var serverToken = null;
    var serverRole = null;

    // Próba weryfikacji w chmurze Render API
    if (window.location.protocol.startsWith("http")) {
        try {
            var res = await fetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ key: raw, hash: inputHash })
            });
            if (res.ok) {
                var data = await res.json();
                if (data && data.success) {
                    serverToken = data.token;
                    serverRole = data.role;
                    localStorage.setItem("lks_render_auth_token", serverToken);
                    localStorage.setItem("lks_render_auth_role", serverRole);
                }
            }
        } catch (e) {
            // Brak serwera / offline
        }
    }

    var role = serverRole || CONFIG.ALLOWED_HASHES[inputHash];

    if (role || serverToken) {
        var authDesc = serverToken ? ("Render Cloud [JWT: " + serverRole + "]") : ("Lokalny SHA-256 [" + role + "]");
        addLog("AUTH_SUCCESS: Zalogowano pomyślnie. " + authDesc, "success");
        localStorage.setItem(CONFIG.SESSION_KEY, "VALID");
        localStorage.setItem(CONFIG.SESSION_DATE_KEY, new Date().toDateString());
        localStorage.setItem(CONFIG.SESSION_HASH_KEY, inputHash);

        var hasRedirected = await sendForwardToReturnUrl(inputHash, serverToken);
        if (hasRedirected) return;

        setTimeout(showHub, 500);
    } else {
        addLog("ERR_ACCESS_DENIED: Niezgodność sumy kontrolnej lub hasła!", "danger");
        if (dom.input) {
            dom.input.value = "";
            updateLiveSha();
        }
        var container = document.getElementById('mainContainer');
        if (container) container.classList.add("lks-frame--access-denied");
        if (dom.statusBarMode) dom.statusBarMode.textContent = "SESJA: ODMOWA_DOSTĘPU";
        if (dom.statusBarLed) {
            dom.statusBarLed.classList.remove("lks-statusbar__led--hub");
            dom.statusBarLed.classList.add("lks-statusbar__led--denied");
        }
        setTimeout(function () {
            if (container) container.classList.remove("lks-frame--access-denied");
            refreshStatusBar();
        }, 450);
    }
}

function showAuth() {
    setAppPhase(1);
    if (dom.auth) dom.auth.classList.add('active');
    if (dom.hub) dom.hub.classList.remove('active');
    addLog("SYS.BOOT: Oczekiwanie na identyfikację kryptograficzną (Render / SHA-256)...", "warning");
}

function showHub() {
    setAppPhase(2);
    if (dom.auth) dom.auth.classList.remove('active');
    if (dom.hub) dom.hub.classList.add('active');
    var storedHash = localStorage.getItem(CONFIG.SESSION_HASH_KEY);
    var storedRole = localStorage.getItem("lks_render_auth_role");
    var role = storedRole || CONFIG.ALLOWED_HASHES[storedHash] || "2_ADMIN";
    if (dom.lvl) {
        dom.lvl.textContent = role;
        dom.lvl.classList.remove("lks-footbar__auth--guest");
        dom.lvl.classList.add("lks-footbar__auth--admin");
    }
    addLog("AUTH.SESSION_ONLINE: Panel Hub aktywny.", "success");
}

async function updateLiveSha() {
    if (!dom.shaLive || !dom.input) return;
    var val = dom.input.value;
    var h = await computeSha256(val);
    dom.shaLive.textContent = h;
}

function quickFill(secret) {
    if (dom.input) {
        dom.input.value = secret;
        updateLiveSha();
    }
}

var activeOpenedWindows = [];
var connectedClients = [];

async function connectToNode(url) {
    if (!url) return;
    url = url.replace(/\/$/, "");
    var token = localStorage.getItem("lks_render_auth_token") || await getShaAuthToken();
    addLog("HANDSHAKE_NODE → " + url, "success");
    var fullUrl = url + (url.indexOf("?") >= 0 ? "&" : "?") + "auth=" + encodeURIComponent(token);
    setTimeout(function () {
        try {
            var w = window.open(fullUrl, "_blank");
            if (w && !activeOpenedWindows.includes(w)) activeOpenedWindows.push(w);
        } catch (e) {
            window.open(fullUrl, "_blank");
        }
    }, 300);
}

// Favicon helpers
function getFaviconUrl(url) {
    var cleanUrl = url.replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
    var ver = "3";
    if (cleanUrl.indexOf("carrd.co") !== -1) {
        return "https://" + cleanUrl + "/assets/images/favicon.png?v=" + ver;
    }
    return "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://" + cleanUrl + "&size=32&v=" + ver;
}

function getFirstLetter(url) {
    try {
        var domain = url.replace(/^https?:\/\//, "").replace(/^www\./, "");
        return domain.charAt(0).toUpperCase();
    } catch (e) { return "?"; }
}

function handleFaviconError(imgElement, url) {
    var attempt = parseInt(imgElement.dataset.attempt, 10) || 1;
    var cleanUrl = url.replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
    var isCarrd = cleanUrl.indexOf("carrd.co") !== -1;
    var ver = "3";

    if (isCarrd) {
        if (attempt === 1) {
            imgElement.src = "https://" + cleanUrl + "/assets/images/apple-touch-icon.png?v=" + ver;
            imgElement.dataset.attempt = "2";
        } else if (attempt === 2) {
            imgElement.src = "https://" + cleanUrl + "/assets/images/favicon.png?v=" + ver;
            imgElement.dataset.attempt = "3";
        } else if (attempt === 3) {
            imgElement.src = "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://" + cleanUrl + "&size=32&v=" + ver;
            imgElement.dataset.attempt = "4";
        } else {
            showFaviconFallback(imgElement);
        }
    } else {
        if (attempt === 1) {
            imgElement.src = "https://" + cleanUrl + "/assets/images/favicon.png";
            imgElement.dataset.attempt = "2";
        } else if (attempt === 2) {
            imgElement.src = "https://www.google.com/s2/favicons?domain=" + cleanUrl + "&sz=32&v=" + ver;
            imgElement.dataset.attempt = "3";
        } else {
            showFaviconFallback(imgElement);
        }
    }
}

var DEFAULT_FAVICON_URL = "favicon/lks_hub.png";

function showFaviconFallback(imgElement) {
    if (!imgElement) return;
    imgElement.onerror = function () {
        imgElement.onerror = null;
        imgElement.src = "https://raw.githubusercontent.com/s-pro-v/guard/refs/heads/main/favicon/lks_hub.png";
    };
    imgElement.src = DEFAULT_FAVICON_URL;
    imgElement.style.display = "block";
    var fallback = imgElement.nextElementSibling;
    if (fallback && fallback.classList.contains("lks-card__favicon-fallback")) {
        fallback.style.display = "none";
    }
}

function loadFaviconsForHub() {
    document.querySelectorAll(".lks-card").forEach(function (card) {
        var url = card.getAttribute("data-url");
        if (!url) return;
        var wrap = card.querySelector(".lks-card__favicon");
        if (!wrap) return;
        var img = wrap.querySelector(".lks-card__favicon-img");
        var fallbackSpan = wrap.querySelector(".lks-card__favicon-fallback");
        if (!img || !fallbackSpan) return;
        fallbackSpan.textContent = getFirstLetter(url);
        img.dataset.attempt = "1";
        img.src = getFaviconUrl(url);
        img.onerror = function () { handleFaviconError(img, url); };
    });
}

function getCardDomain(url) {
    return (url || "").replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
}

function escapeHtml(text) {
    var div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

function renderHubGrid(cards) {
    var grid = document.getElementById("hubGrid");
    if (!grid) return;
    grid.innerHTML = "";
    hubNodeCount = 0;
    if (!Array.isArray(cards) || cards.length === 0) {
        refreshStatusBar();
        return;
    }

    cards.forEach(function (item) {
        var url = (item.url || item.href || "").trim();
        var title = item.title || "SYS_NODE";
        var description = item.description || item.desc || "NO_DATA";
        var cardImage = (
            item.image ||
            item.img ||
            item.bg ||
            item.background ||
            item.media ||
            item.thumbnail ||
            item.thumb ||
            item.cover ||
            item.cardImage ||
            ""
        ).trim();
        if (!url) return;
        hubNodeCount++;

        var carrdShareImg = "";
        if (/\.carrd\.co/i.test(url)) {
            carrdShareImg = url.replace(/\/+$/, "") + "/assets/images/share.jpg";
        }

        var screenshotUrl = "https://image.thum.io/get/width/500/crop/280/noanimate/" + url;
        var fallbackMshots = "https://s0.wp.com/mshots/v1/" + encodeURIComponent(url) + "?w=500&h=280";

        var bodyBgStyle = "";
        if (cardImage) {
            bodyBgStyle = "background-image: url('" + cardImage.replace(/'/g, "\\'") + "');";
        } else if (carrdShareImg) {
            bodyBgStyle = "background-image: url('" + carrdShareImg.replace(/'/g, "\\'") + "'), url('" + screenshotUrl + "'), url('" + fallbackMshots + "');";
        } else {
            bodyBgStyle = "background-image: url('" + screenshotUrl + "'), url('" + fallbackMshots + "');";
        }

        var a = document.createElement("a");
        a.className = "lks-card";
        a.href = url;
        a.setAttribute("data-url", url);

        a.innerHTML =
            "<div class=\"lks-card__head\">" +
            "<div class=\"lks-card__favicon\">" +
            "<img class=\"lks-card__favicon-img\" alt=\"\" src=\"" + getFaviconUrl(url) + "\" />" +
            "<span class=\"lks-card__favicon-fallback\"></span>" +
            "</div>" +
            "<h3>" + escapeHtml(title) + "</h3>" +
            "</div>" +
            "<div class=\"lks-card__media\" style=\"" + bodyBgStyle + "\"></div>" +
            "<p>" + escapeHtml(description) + "</p>";

        grid.appendChild(a);
    });
    loadFaviconsForHub();
    refreshStatusBar();
}

function loadHubGrid() {
    var url = CONFIG.CARDS_URL;
    pageLoadingStartedAt = pageLoadingNow();
    setPageLoadActivity("Pobieranie katalogu węzłów i sum SHA-256…", 30);
    syncPageLoadSessionLine();
    var safety = setTimeout(dismissPageLoadingOverlay, PAGE_LOADING_SAFETY_MS);

    fetch(url)
        .then(function (res) {
            setPageLoadActivity("Walidacja odpowiedzi serwera i odczyt listy…", 50);
            return res.ok ? res.json() : Promise.reject(new Error(res.status));
        })
        .then(function (data) {
            setPageLoadActivity("Budowa punktów wejścia OXY_OS…", 75);
            var cards = Array.isArray(data) ? data : (data.cards || data.items || []);
            renderHubGrid(cards);
        })
        .catch(function () {
            setPageLoadActivity("Błąd sieci — brak węzłów card.json…", 50);
            renderHubGrid([]);
            if (dom.terminal) addLog("FETCH_ERR: Nie udało się pobrać card.json.", "warning");
        })
        .finally(function () {
            setPageLoadActivity("Inicjalizacja kryptograficzna zakończona.", 100);
            syncPageLoadSessionLine();
            clearTimeout(safety);
            var elapsed = pageLoadingNow() - pageLoadingStartedAt;
            var wait = Math.max(0, PAGE_LOADING_MIN_MS - elapsed);
            setTimeout(dismissPageLoadingOverlay, wait);
        });
}

function toggleTheme() {
    var root = document.documentElement;
    var cur = root.getAttribute("theme") || "dark";
    var next = cur === "dark" ? "light" : "dark";
    root.classList.add("theme-switching");
    root.setAttribute("theme", next);
    try {
        localStorage.setItem(CONFIG.THEME_KEY, next);
    } catch (e) { }
    requestAnimationFrame(function () {
        requestAnimationFrame(function () {
            root.classList.remove("theme-switching");
        });
    });
    if (window.lucide && typeof window.lucide.createIcons === "function") {
        window.lucide.createIcons();
    }
    if (dom.terminal) {
        addLog("THEME :: " + next.toUpperCase(), "");
    }
    refreshStatusBar();
}

function logout() {
    localStorage.removeItem(CONFIG.SESSION_KEY);
    localStorage.removeItem(CONFIG.SESSION_DATE_KEY);
    localStorage.removeItem(CONFIG.SESSION_HASH_KEY);
    localStorage.removeItem("lks_render_auth_token");
    localStorage.removeItem("lks_render_auth_role");
    localStorage.setItem("lks_vault_logout_signal", String(Date.now()));
    addLog("SYS.LOGOUT: Klucze sesyjne wyczyszczone — sesja NIEAKTUALNA.", "warning");

    var logoutPayload = {
        type: "LKS_GUARD_LOGOUT",
        valid: false,
        status: "NIEAKTUALNA"
    };

    // 1. Rozesłanie sygnału wylogowania do wszystkich otwartych węzłów i połączonych klientów
    var allClients = activeOpenedWindows.concat(connectedClients);
    allClients.forEach(function (w) {
        try {
            if (w && !w.closed) {
                w.postMessage(logoutPayload, "*");
                w.postMessage({ type: "LKS_SESSION_STATUS", valid: false, status: "NIEAKTUALNA" }, "*");
            }
        } catch (e) { }
    });

    // 2. BroadcastChannel dla kart
    try {
        var bc = new BroadcastChannel("lks_channel");
        bc.postMessage(logoutPayload);
        bc.close();
    } catch (e) { }

    try {
        window.postMessage(logoutPayload, "*");
    } catch (e) { }

    if (window.parent && window.parent !== window) {
        try {
            window.parent.postMessage(logoutPayload, "*");
        } catch (e) { }
    }

    setTimeout(function () {
        showAuth();
        refreshStatusBar();
        if (dom.input) {
            dom.input.value = "";
            updateLiveSha();
        }
    }, 350);
}

// IPC Listener do integracji między oknami/kartami
window.addEventListener("message", async function (event) {
    if (!event.data || typeof event.data !== "object") return;

    // Automatyczna rejestracja okna klienta, który przysłał zapytanie
    if (event.source && event.source !== window && !connectedClients.includes(event.source)) {
        connectedClients.push(event.source);
    }

    if (event.data.type === "LKS_SESSION_CHECK") {
        var isValid = isCurrentlyLoggedIn();
        var authToken = isValid ? await getShaAuthToken() : null;

        if (event.source && event.source.postMessage) {
            event.source.postMessage({
                type: "LKS_SESSION_STATUS",
                valid: isValid,
                status: isValid ? "AKTUALNA" : "NIEAKTUALNA",
                authToken: authToken,
                date: new Date().toDateString()
            }, "*");
        }
    }
});

// MODAL KODU KLIENTA DLA STRON (RENDER CLOUD & OFFLINE SHA)
var currentClientTab = "render_one";

function getEffectiveHubUrl() {
    var input = document.getElementById("renderHubUrlInput");
    var custom = input ? input.value.trim() : "";
    if (custom) return custom.replace(/\/$/, "");

    if (typeof window !== "undefined" && window.location && window.location.origin) {
        if (window.location.protocol.startsWith("http")) {
            return window.location.origin;
        }
    }
    return "https://twoj-serwis.onrender.com";
}

function switchClientTab(tabName) {
    currentClientTab = tabName;
    var btnOne = document.getElementById("tabRenderOne");
    var btnInline = document.getElementById("tabRenderInline");
    var btnSha = document.getElementById("tabClassicSha");

    if (btnOne) btnOne.style.borderColor = tabName === "render_one" ? "var(--highlight-color)" : "";
    if (btnInline) btnInline.style.borderColor = tabName === "render_inline" ? "var(--highlight-color)" : "";
    if (btnSha) btnSha.style.borderColor = tabName === "classic_sha" ? "var(--highlight-color)" : "";

    updateClientSnippetView();
}

function updateClientSnippetView() {
    var txt = document.getElementById("clientCodeSnippet");
    if (!txt) return;

    var hubUrl = getEffectiveHubUrl();

    if (currentClientTab === "render_one") {
        txt.value = "<!-- ============================================== -->\n" +
            "<!-- LKS GUARD // RENDER CLOUD AUTH (1 LINIA KODU) -->\n" +
            "<!-- Wklej ponizszy znacznik w <head> lub Embed na Carrd -->\n" +
            "<!-- ============================================== -->\n" +
            "<script src=\"" + hubUrl + "/api/auth/client.js\"><\/script>";
    } else if (currentClientTab === "render_inline") {
        var inlineCode = "(function () {\n  \"use strict\";\n\n  var HUB_URL = \"%%HUB_URL%%\";\n  var SK = \"lks_vault_auth\";\n  var SDK = \"lks_vault_auth_date\";\n  var TOKEN_KEY = \"lks_render_auth_token\";\n  var ALLOWED_HASHES = [\"3cdf2dabfe18fb4d0e1f39fc86f836ed20ef0510d0f373b8071417906842bb93\"];\n\n  var d = document;\n  var $ = function (i) { return d.getElementById(i); };\n  function b() { return d.body || d.documentElement; }\n\n  if ($(\"L0\")) return;\n\n  // 1. Wstrzyknięcie czcionki i stylów LKS GUARD\n  (function injectStyles() {\n    if (d.getElementById(\"Z\")) return;\n\n    var fontLink = d.createElement(\"link\");\n    fontLink.rel = \"stylesheet\";\n    fontLink.href = \"https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&display=swap\";\n    (d.head || d.documentElement).appendChild(fontLink);\n\n    var css = `\n:root {\n    --shadow-drop: rgba(32, 32, 32, 0.4) 0px 0px 0px 2px, rgba(0, 0, 0, 0.65) 0px 4px 6px -1px, rgba(255, 255, 255, 0.08) 0px 1px 0px inset;\n    --shadow-inset: inset 0px 0px 0px 2px rgba(32, 32, 32, 0.4), inset 0px 4px 6px -1px rgba(0, 0, 0, 0.65), inset 0px 1px 0px rgba(255, 255, 255, 0.08);\n    --shadow-hover: rgba(32, 32, 32, 0.2) 0px 0px 0px 1px, rgba(0, 0, 0, 0.325) 0px 2px 3px -0.5px, rgba(255, 255, 255, 0.04) 0px 0.5px 0px inset;\n    --padding: 0.125rem;\n    --gap: 0.125rem;\n    --bg-tertiary: #2e2e2e;\n    --border-color: #2a2a2a;\n    --panel-bg: #2a2a2a;\n    --card-bg: #1e1e1e;\n    --text-muted: #858585;\n    --text-color: #e0e0e0;\n    --highlight-color: #f36c00;\n    --accent-ok: #09b83e;\n    --border-color-hover: #444444;\n    --hover-bg: #3c3c3c;\n    --font-family: \"JetBrains Mono\", monaco, courier, monospace;\n    --font-main: var(--font-family);\n    --transition-speed: 0.2s;\n    --transition-ease: ease;\n    --transition-ui: background-color var(--transition-speed) var(--transition-ease),\n        color var(--transition-speed) var(--transition-ease),\n        border-color var(--transition-speed) var(--transition-ease),\n        box-shadow var(--transition-speed) var(--transition-ease);\n}\n\n#L0, #L0 *, #L0 *::before, #L0 *::after {\n    border-radius: 0 !important;\n    box-sizing: border-box;\n}\n\nbody * {\n    visibility: hidden !important;\n}\n\n#L0, #L0 * {\n    visibility: visible !important;\n}\n\nbody.lks-guard-passed * {\n    visibility: visible !important;\n}\n\n#L0 {\n    position: fixed;\n    inset: 0;\n    z-index: 2147483647;\n    display: flex;\n    align-items: center;\n    justify-content: center;\n    background-color: var(--card-bg);\n    background-image:\n        linear-gradient(rgba(255, 255, 255, 0.025) 1px, transparent 1px),\n        linear-gradient(90deg, rgba(255, 255, 255, 0.025) 1px, transparent 1px),\n        linear-gradient(rgba(18, 18, 18, 0.76), rgba(18, 18, 18, 0.62)),\n        url('https://raw.githubusercontent.com/s-pro-v/os_pro/refs/heads/main/assets/images/bg4.jpg');\n    background-size: 24px 24px, 24px 24px, cover, cover;\n    background-position: center;\n    font-family: var(--font-family);\n    user-select: none;\n    -webkit-user-select: none;\n    transition: opacity 0.3s ease, visibility 0.3s ease;\n}\n\n#L0.d, #L0.d * {\n    opacity: 0;\n    visibility: hidden !important;\n    pointer-events: none;\n}\n\n#L0 .btn-bg {\n    display: flex;\n    justify-content: center;\n    align-items: center;\n    box-shadow: var(--shadow-inset);\n    padding: var(--padding);\n    gap: var(--gap);\n    position: relative;\n    overflow: hidden;\n    width: fit-content;\n    border: 1px solid var(--border-color);\n    background: var(--card-bg);\n    transition: var(--transition-ui);\n}\n\n#L0 .btn-bg:hover {\n    border: 1px solid var(--border-color-hover);\n}\n\n#L0 .btn {\n    box-shadow: var(--shadow-drop);\n    border: 1px solid var(--border-color);\n    background: var(--bg-tertiary);\n    color: var(--text-muted);\n    width: 100px;\n    height: 30px;\n    transition: var(--transition-ui);\n    font-family: var(--font-family);\n    font-weight: 700;\n    display: flex;\n    align-items: center;\n    margin: 0;\n}\n\n#L0 .btn:hover {\n    background: var(--hover-bg);\n    color: var(--text-color);\n    border: 1px solid var(--border-color-hover);\n    box-shadow: var(--shadow-hover);\n}\n\n#L0 .btn:active {\n    box-shadow: var(--shadow-inset);\n    background: var(--panel-bg);\n    color: var(--text-muted);\n    border: 1px solid var(--border-color);\n}\n\n#L0 .lks-outer-frame {\n    padding: 0.125rem;\n    background: #181818;\n    border: 1px solid var(--border-color);\n}\n\n#L0 .lks-outer-frame::before,\n#L0 .lks-outer-frame::after {\n    content: \"\";\n    position: absolute;\n    width: 10px;\n    height: 10px;\n    border: 1px solid var(--highlight-color);\n    pointer-events: none;\n    z-index: 3;\n    opacity: 0.75;\n}\n\n#L0 .lks-outer-frame::before {\n    top: 2px;\n    left: 2px;\n    border-right: none;\n    border-bottom: none;\n}\n\n#L0 .lks-outer-frame::after {\n    bottom: 2px;\n    right: 2px;\n    border-left: none;\n    border-top: none;\n}\n\n#L0 #L1.lks-chassis {\n    display: flex;\n    flex-direction: column;\n    align-items: stretch;\n    width: 390px;\n    max-width: 92vw;\n    height: auto;\n    padding: 0.375rem;\n    gap: 0.125rem;\n    background-color: var(--panel-bg);\n    background-image:\n        linear-gradient(rgba(255, 255, 255, 0.018) 1px, transparent 1px),\n        linear-gradient(90deg, rgba(255, 255, 255, 0.018) 1px, transparent 1px);\n    background-size: 12px 12px;\n    border: 1px solid var(--border-color);\n    text-transform: uppercase;\n}\n\n#L0 #L1.lks-chassis:hover {\n    background-color: var(--panel-bg);\n    border: 1px solid var(--border-color-hover);\n}\n\n#L0 .lks-row {\n    display: flex;\n    width: 100%;\n    gap: var(--gap);\n}\n\n#L0 .lks-grow {\n    flex: 1;\n    width: 40%;\n    height: fit-content;\n}\n\n#L0 .lks-full {\n    width: 100%;\n}\n\n#L0 .lks-led-box {\n    width: 28px;\n    height: 26px;\n    justify-content: center;\n    background: var(--card-bg);\n}\n\n#L0 #L-led {\n    display: block;\n    width: 6px;\n    height: 6px;\n    background: var(--highlight-color);\n    box-shadow: 0 0 6px var(--highlight-color);\n}\n\n#L0 .lks-telemetry {\n    width: 100%;\n    height: 26px;\n    padding: 0 0.5rem;\n    justify-content: space-between;\n    font-size: 10px;\n    letter-spacing: 0.06rem;\n    background: var(--card-bg);\n}\n\n#L0 .t-ok {\n    color: var(--highlight-color);\n    font-weight: 800;\n}\n\n#L0 .t-ses {\n    color: var(--text-color);\n    opacity: 0.85;\n}\n\n#L0 .t-clock {\n    color: var(--highlight-color);\n    font-weight: 700;\n}\n\n#L0 .lks-tile {\n    width: 100%;\n    height: 54px;\n    padding: 0 0.5rem 0 0.75rem;\n    justify-content: space-between;\n    background: linear-gradient(180deg, #323232 0%, #262626 100%);\n    border: 1px solid var(--border-color);\n}\n\n#L0 .lks-tile:hover {\n    background: linear-gradient(180deg, #3a3a3a 0%, #2c2c2c 100%);\n    border: 1px solid var(--border-color-hover);\n}\n\n#L0 .lks-tile-info {\n    display: flex;\n    flex-direction: column;\n    justify-content: center;\n    gap: 0.125rem;\n    text-align: left;\n}\n\n#L0 #L2 {\n    margin: 0;\n    font-size: 13px;\n    font-weight: 800;\n    letter-spacing: 0.08rem;\n    color: var(--text-color);\n    line-height: 1;\n}\n\n#L0 .lks-sub {\n    font-size: 9px;\n    font-weight: 700;\n    letter-spacing: 0.06rem;\n    color: var(--text-muted);\n    opacity: 0.65;\n    line-height: 1;\n}\n\n#L0 .lks-icon-slot {\n    padding: var(--padding);\n    background: var(--card-bg);\n}\n\n#L0 #L2-badge.lks-icon-btn {\n    width: 32px;\n    height: 32px;\n    justify-content: center;\n    background: var(--bg-tertiary);\n    color: var(--highlight-color);\n    border: 1px solid var(--border-color);\n}\n\n#L0 #L2-badge.lks-icon-btn:hover {\n    border: 1px solid var(--border-color-hover);\n    color: var(--text-color);\n}\n\n#L0 #L3.lks-msg {\n    width: 100%;\n    height: 30px;\n    padding: 0 0.625rem;\n    font-size: 10px;\n    letter-spacing: 0.1rem;\n    color: var(--text-muted);\n    justify-content: flex-start;\n}\n\n#L0 #L3.lks-msg::before {\n    content: \"SYS_MSG // \";\n    color: var(--highlight-color);\n    opacity: 0.75;\n    margin-right: 0.35rem;\n}\n\n/* MATRYCA KWADRACIKÓW SKANERA */\n#L0 .lks-row.L {\n    justify-content: space-between;\n    gap: 0.125rem;\n}\n\n#L0 .L .btn-bg {\n    flex: 1;\n    padding: 0.125rem;\n    aspect-ratio: 1 / 1;\n    max-width: 15px;\n}\n\n#L0 .L b.btn {\n    width: 100%;\n    height: 100%;\n    min-width: 6px;\n    min-height: 6px;\n    aspect-ratio: 1 / 1;\n    background: var(--bg-tertiary);\n    border: 1px solid var(--border-color);\n    animation: lks-scan 1.2s infinite steps(1);\n}\n\n#L0 .L b.btn:hover {\n    border: 1px solid var(--border-color-hover);\n}\n\n#L0 .L .btn-bg:nth-child(6n+1) b.btn { animation-delay: 0s; }\n#L0 .L .btn-bg:nth-child(6n+2) b.btn { animation-delay: 0.15s; }\n#L0 .L .btn-bg:nth-child(6n+3) b.btn { animation-delay: 0.3s; }\n#L0 .L .btn-bg:nth-child(6n+4) b.btn { animation-delay: 0.45s; }\n#L0 .L .btn-bg:nth-child(6n+5) b.btn { animation-delay: 0.6s; }\n#L0 .L .btn-bg:nth-child(6n+6) b.btn { animation-delay: 0.75s; }\n\n@keyframes lks-scan {\n    0%, 100% {\n        background: var(--bg-tertiary);\n        border-color: var(--border-color);\n    }\n    50% {\n        background: var(--highlight-color);\n        border-color: var(--border-color-hover);\n    }\n}\n\n#L0 #L4.lks-bar-slot {\n    width: 100%;\n    height: 15px;\n    padding: var(--padding);\n    background: var(--card-bg);\n    box-shadow: var(--shadow-inset);\n    border: 1px solid var(--border-color);\n    overflow: hidden;\n}\n\n#L0 #L4.lks-bar-slot:hover {\n    border: 1px solid var(--border-color-hover);\n}\n\n#L0 #L5.btn {\n    width: 0%;\n    height: 100%;\n    background: var(--highlight-color);\n    border: 1px solid var(--border-color);\n    box-shadow: var(--shadow-drop);\n}\n\n#L0 #L5.btn:hover {\n    border: 1px solid var(--border-color-hover);\n}\n\n#L0 #L6.lks-pct {\n    width: 58px;\n    height: 15px;\n    justify-content: center;\n    font-size: 10px;\n    letter-spacing: 0.06rem;\n    color: var(--highlight-color);\n}\n\n#L0 #L1.ok #L-led {\n    background: var(--accent-ok);\n    box-shadow: 0 0 6px var(--accent-ok);\n}\n\n#L0 #L1.ok .t-ok,\n#L0 #L1.ok .t-ses {\n    color: var(--accent-ok);\n}\n\n#L0 #L1.ok #L2-badge.lks-icon-btn {\n    color: var(--accent-ok);\n    border-color: var(--border-color);\n}\n\n#L0 #L1.ok #L2-badge.lks-icon-btn:hover {\n    border-color: var(--border-color-hover);\n}\n\n#L0 #L1.ok #L3,\n#L0 #L1.ok #L3::before {\n    color: var(--accent-ok);\n}\n\n#L0 #L1.ok #L3:empty::after {\n    content: \"ACCESS_GRANTED // SESJA AKTYWNA\";\n    color: var(--accent-ok);\n}\n\n#L0 #L1.ok #L5.btn {\n    background: var(--accent-ok);\n    border-color: var(--border-color);\n    animation: lks-load 1.65s linear forwards;\n}\n\n#L0 #L1.ok .L b.btn {\n    background: var(--accent-ok);\n    border-color: var(--border-color);\n    animation-timing-function: steps(2, end);\n    animation-iteration-count: infinite;\n}\n\n#L0 #L1.ok .L .btn-bg:nth-child(3n+1) b.btn { animation-name: srv-a; animation-duration: 0.55s; animation-delay: -0.18s; }\n#L0 #L1.ok .L .btn-bg:nth-child(3n+2) b.btn { animation-name: srv-b; animation-duration: 0.85s; animation-delay: -0.54s; }\n#L0 #L1.ok .L .btn-bg:nth-child(3n+3) b.btn { animation-name: srv-c; animation-duration: 0.68s; animation-delay: -0.31s; }\n\n#L0 #L1.er #L-led {\n    background: var(--highlight-color);\n    box-shadow: 0 0 8px var(--highlight-color);\n}\n\n#L0 #L1.er .t-ok,\n#L0 #L1.er .t-ses,\n#L0 #L1.er #L2,\n#L0 #L1.er #L3,\n#L0 #L1.er #L2-badge {\n    color: var(--highlight-color);\n}\n\n#L0 #L1.er #L3::before {\n    content: \"ERR_CODE // \";\n}\n\n#L0 #L1.er .L b.btn {\n    background: var(--highlight-color);\n    border-color: var(--border-color);\n    opacity: 0.45;\n}\n\n#L0 #L1.er #L5.btn {\n    width: 100%;\n    background: var(--highlight-color);\n    border-color: var(--border-color);\n}\n\n@keyframes lks-load {\n    0% { width: 0%; }\n    25% { width: 25%; }\n    31% { width: 25%; }\n    65% { width: 65%; }\n    80% { width: 65%; }\n    100% { width: 100%; }\n}\n\n@keyframes srv-a {\n    0%, 100% { opacity: 0.25; }\n    50% { opacity: 1; }\n}\n@keyframes srv-b {\n    0%, 100% { opacity: 0.45; }\n    58% { opacity: 1; }\n}\n@keyframes srv-c {\n    0%, 100% { opacity: 0.15; }\n    68% { opacity: 1; }\n}\n`;\n    var s = d.createElement(\"style\");\n    s.id = \"Z\";\n    s.textContent = css;\n    (d.head || d.documentElement).appendChild(s);\n  })();\n\n  var ICON_LOCK = '<svg viewBox=\"0 0 24 24\" width=\"15\" height=\"15\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"4\" y=\"11\" width=\"16\" height=\"10\"/><path d=\"M8 11V7a4 4 0 0 1 8 0v4\"/></svg>';\n  var ICON_OK = '<svg viewBox=\"0 0 24 24\" width=\"15\" height=\"15\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.2\"><path d=\"M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3z\"/><path d=\"M9 12l2 2 4-4\"/></svg>';\n  var ICON_ERR = '<svg viewBox=\"0 0 24 24\" width=\"15\" height=\"15\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.2\"><path d=\"M12 2L2 20h20L12 2z\"/><path d=\"M12 9v5\"/><path d=\"M12 16h.01\"/></svg>';\n\n  function clearSess() {\n    try {\n      sessionStorage.removeItem(SK);\n      sessionStorage.removeItem(SDK);\n      localStorage.removeItem(SK);\n      localStorage.removeItem(SDK);\n      localStorage.removeItem(TOKEN_KEY);\n    } catch (e) {}\n  }\n\n  function sessOk() {\n    var t = new Date().toDateString(),\n      x = sessionStorage.getItem(SK) || localStorage.getItem(SK),\n      y = sessionStorage.getItem(SDK) || localStorage.getItem(SDK);\n    if (x === \"VALID\" && y !== t) {\n      clearSess();\n      return 0;\n    }\n    return x === \"VALID\" && y === t;\n  }\n\n  function pad(n) { return (n < 10 ? \"0\" : \"\") + n; }\n\n  function updateNavStatus(state, label, status) {\n    var codeEl = $(\"L-st-code\"), lblEl = $(\"L-st-lbl\");\n    if (codeEl && label) codeEl.textContent = label;\n    if (lblEl && status) lblEl.textContent = status;\n  }\n\n  var clockId = 0;\n  function startNavClock() {\n    if (clockId) return;\n    function tick() {\n      var t = new Date(),\n        dateStr = pad(t.getDate()) + \".\" + pad(t.getMonth() + 1) + \".\" + t.getFullYear(),\n        timeStr = pad(t.getHours()) + \":\" + pad(t.getMinutes()) + \":\" + pad(t.getSeconds()),\n        mDate = $(\"L-date\"),\n        mTime = $(\"L-time\");\n      if (mDate) mDate.textContent = dateStr;\n      if (mTime) mTime.textContent = timeStr;\n    }\n    tick();\n    clockId = setInterval(tick, 1000);\n  }\n\n  function setSt(x, w) {\n    var p = $(\"L1\"), a = $(\"L2\"), bg = $(\"L2-badge\"), s = $(\"L3\");\n    if (p) p.classList.remove(\"er\");\n    if (w) {\n      if (p) p.classList.add(\"ok\");\n      if (a) a.textContent = \"GUARD // OK\";\n      if (bg) bg.innerHTML = ICON_OK;\n      if (s) s.textContent = x || \"\";\n      updateNavStatus(\"ok\", \"OK\", \"SESJA\");\n    } else if (s && x) s.textContent = x;\n  }\n\n  function hide() {\n    var e = b();\n    e.classList.add(\"lks-guard-passed\");\n    e.classList.remove(\"lks-page-loading\");\n    var o = $(\"L0\");\n    if (o) o.classList.add(\"d\");\n  }\n\n  function redir(e) {\n    clearSess();\n    var o = $(\"L0\"), p = $(\"L1\"), a = $(\"L2\"), bg = $(\"L2-badge\"), s = $(\"L3\");\n    if (o) {\n      b().classList.remove(\"lks-guard-passed\");\n      b().classList.add(\"lks-page-loading\");\n      o.classList.remove(\"d\");\n    }\n    updateNavStatus(\"stop\", \"STOP\", e ? \"SESJA\" : \"BRAK\");\n    if (p) { p.classList.remove(\"ok\"); p.classList.add(\"er\"); }\n    if (a) a.textContent = \"GUARD // STOP\";\n    if (bg) bg.innerHTML = ICON_ERR;\n    if (s) s.textContent = e ? \"Sesja wygasła → Hub\" : \"Brak autoryzacji → Hub\";\n    var g = HUB_URL || location.origin + \"/\",\n      u = location.origin + location.pathname;\n    setTimeout(function () {\n      var sep = g.indexOf(\"?\") >= 0 ? \"&\" : \"?\";\n      location.replace(g + sep + \"return_url=\" + encodeURIComponent(u));\n    }, 1000);\n  }\n\n  function watch() {\n    function k() {\n      if (!d.hidden && !sessOk()) redir(1);\n      checkHubSession();\n    }\n    setInterval(k, 1500);\n    d.addEventListener(\"visibilitychange\", function () {\n      if (!d.hidden) k();\n    });\n  }\n\n  function go() {\n    setSt(\"\", 1);\n    var bar = $(\"L5\"), pct = $(\"L6\"), done = 0;\n    function finish() {\n      if (done) return;\n      done = 1;\n      if (pct) pct.textContent = \"100%\";\n      hide();\n      updateNavStatus(\"ok\", \"OK\", \"SESJA\");\n      startNavClock();\n      watch();\n    }\n    function showProgress(start) {\n      var elapsed = Math.min((performance.now() - start) / 2650, 1), value;\n      if (elapsed < 0.25) value = elapsed * 100;\n      else if (elapsed < 0.31) value = 25;\n      else if (elapsed < 0.65) value = 25 + ((elapsed - 0.31) / 0.34) * 40;\n      else if (elapsed < 0.8) value = 65;\n      else value = 65 + ((elapsed - 0.8) / 0.2) * 35;\n      if (pct) pct.textContent = Math.min(100, Math.round(value)) + \"%\";\n      if (!done && elapsed < 1) requestAnimationFrame(function () { showProgress(start); });\n    }\n    showProgress(performance.now());\n    if (bar) bar.addEventListener(\"animationend\", finish, { once: true });\n    setTimeout(finish, bar ? 3200 : 0);\n  }\n\n  async function sha256(t) {\n    if (!t) return \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\";\n    if (window.crypto && crypto.subtle && crypto.subtle.digest) {\n      var buf = await crypto.subtle.digest(\"SHA-256\", new TextEncoder().encode(t));\n      return Array.from(new Uint8Array(buf)).map(function (x) { return x.toString(16).padStart(2, \"0\"); }).join(\"\");\n    }\n    return \"\";\n  }\n\n  function checkHubSession() {\n    if (window.opener && !window.opener.closed) {\n      try { window.opener.postMessage({ type: \"LKS_SESSION_CHECK\" }, \"*\"); } catch (e) {}\n    }\n  }\n\n  window.addEventListener(\"message\", function (e) {\n    if (!e.data || typeof e.data !== \"object\") return;\n    if (e.data.type === \"LKS_GUARD_LOGOUT\" || (e.data.type === \"LKS_SESSION_STATUS\" && e.data.valid === false)) {\n      clearSess();\n      redir(1);\n    }\n  });\n\n  window.addEventListener(\"storage\", function (e) {\n    if ((e.key === SK && e.newValue !== \"VALID\") || e.key === \"lks_vault_logout_signal\") {\n      clearSess();\n      redir(1);\n    }\n  });\n\n  try {\n    var bc = new BroadcastChannel(\"lks_channel\");\n    bc.onmessage = function (e) {\n      if (e.data && (e.data.type === \"LKS_GUARD_LOGOUT\" || e.data.valid === false)) {\n        clearSess();\n        redir(1);\n      }\n    };\n  } catch (e) {}\n\n  if (window.opener && !window.opener.closed) {\n    try { window.opener.postMessage({ type: \"LKS_REGISTER_CLIENT\" }, \"*\"); } catch (e) {}\n  }\n  window.addEventListener(\"focus\", checkHubSession);\n\n  async function run() {\n    var q = new URLSearchParams(location.search);\n    if (q.get(\"lks_logout\") === \"1\") {\n      clearSess();\n      history.replaceState({}, d.title, location.origin + location.pathname);\n      location.replace(HUB_URL || location.origin + \"/\");\n      return;\n    }\n\n    var n = q.get(\"auth\");\n    var day = new Date().getDate();\n\n    // 1. Sprawdzenie tokenu z parametru URL\n    if (n) {\n      try {\n        var verifyUrl = HUB_URL.replace(/\\/$/, \"\") + \"/api/auth/verify?token=\" + encodeURIComponent(n);\n        var res = await fetch(verifyUrl, { method: \"GET\", headers: { \"Accept\": \"application/json\" } });\n        if (res.ok) {\n          var data = await res.json();\n          if (data && data.valid) {\n            sessionStorage.setItem(SK, \"VALID\");\n            sessionStorage.setItem(SDK, new Date().toDateString());\n            localStorage.setItem(TOKEN_KEY, n);\n            history.replaceState({}, d.title, location.origin + location.pathname);\n            go();\n            checkHubSession();\n            return;\n          }\n        }\n      } catch (err) {}\n\n      // Fallback SHA-256\n      for (var i = 0; i < ALLOWED_HASHES.length; i++) {\n        var exp = await sha256(ALLOWED_HASHES[i] + \"_\" + day);\n        if (n.toLowerCase() === exp.toLowerCase()) {\n          sessionStorage.setItem(SK, \"VALID\");\n          sessionStorage.setItem(SDK, new Date().toDateString());\n          history.replaceState({}, d.title, location.origin + location.pathname);\n          go();\n          checkHubSession();\n          return;\n        }\n      }\n      clearSess();\n      redir(0);\n      return;\n    }\n\n    // 2. Sprawdzenie tokenu w pamięci podręcznej (Render JWT)\n    var savedToken = localStorage.getItem(TOKEN_KEY);\n    if (savedToken) {\n      try {\n        var vUrl = HUB_URL.replace(/\\/$/, \"\") + \"/api/auth/verify?token=\" + encodeURIComponent(savedToken);\n        var vRes = await fetch(vUrl, { method: \"GET\", headers: { \"Accept\": \"application/json\" } });\n        if (vRes.ok) {\n          var vData = await vRes.json();\n          if (vData && vData.valid) {\n            sessionStorage.setItem(SK, \"VALID\");\n            sessionStorage.setItem(SDK, new Date().toDateString());\n            go();\n            return;\n          }\n        }\n      } catch (e) {}\n    }\n\n    if (window.opener && !window.opener.closed) {\n      checkHubSession();\n      if (sessOk()) { go(); return; }\n      redir(0);\n      return;\n    }\n\n    if (sessOk()) { go(); return; }\n\n    // Dopuszczalność podglądu w środowisku czysto lokalnym\n    if (location.protocol === \"file:\" || location.hostname === \"localhost\" || location.hostname === \"127.0.0.1\") {\n      go();\n      return;\n    }\n\n    clearSess();\n    redir(0);\n  }\n\n  function mount() {\n    try { build(); } catch (e) { hide(); throw e; }\n  }\n\n  function build() {\n    var e = b();\n    e.classList.add(\"lks-page-loading\");\n\n    var leds = \"\";\n    for (var k = 0; k < 24; k++) {\n      leds += '<div class=\"btn-bg\"><b class=\"btn\"></b></div>';\n    }\n\n    var o = d.createElement(\"div\");\n    o.id = \"L0\";\n    o.innerHTML =\n      '<div class=\"btn-bg lks-outer-frame\">' +\n        '<div id=\"L1\" class=\"btn lks-chassis\">' +\n          '<div class=\"lks-row lks-top-bar\">' +\n            '<div class=\"btn-bg\"><div class=\"btn lks-led-box\"><i id=\"L-led\"></i></div></div>' +\n            '<div class=\"btn-bg lks-grow\">' +\n              '<div class=\"btn lks-telemetry\">' +\n                '<span id=\"L-st-code\" class=\"t-ok\">WAIT</span>' +\n                '<span id=\"L-st-lbl\" class=\"t-ses\">SESJA</span>' +\n                '<span id=\"L-date\" class=\"t-clock\">--.--.----</span>' +\n                '<span id=\"L-time\" class=\"t-clock\">--:--:--</span>' +\n              '</div>' +\n            '</div>' +\n          '</div>' +\n          '<div class=\"btn-bg lks-full\">' +\n            '<div class=\"btn lks-tile\">' +\n              '<div class=\"lks-tile-info\">' +\n                '<p id=\"L2\">LKS_GUARD</p>' +\n                '<span class=\"lks-sub\">SECURITY GATE // RENDER CLOUD</span>' +\n              '</div>' +\n              '<div class=\"btn-bg lks-icon-slot\">' +\n                '<span id=\"L2-badge\" class=\"btn lks-icon-btn\">' + ICON_LOCK + '</span>' +\n              '</div>' +\n            '</div>' +\n          '</div>' +\n          '<div class=\"btn-bg lks-full\"><p id=\"L3\" class=\"btn lks-msg\">Weryfikacja sesji…</p></div>' +\n          '<div class=\"lks-row L\">' + leds + '</div>' +\n          '<div class=\"lks-row\">' +\n            '<div class=\"btn-bg lks-grow\"><div id=\"L4\" class=\"btn lks-bar-slot\"><div id=\"L5\" class=\"btn\"></div></div></div>' +\n            '<div class=\"btn-bg\"><div id=\"L6\" class=\"btn lks-pct\">0%</div></div>' +\n          '</div>' +\n        '</div>' +\n      '</div>';\n    e.appendChild(o);\n    startNavClock();\n    run();\n  }\n\n  if (d.readyState === \"loading\") d.addEventListener(\"DOMContentLoaded\", mount);\n  else mount();\n})();\n".replace("%%HUB_URL%%", hubUrl);
        txt.value = "<script>\n" + inlineCode + "\n<\/script>";
    } else {
        var currentHashes = JSON.stringify(Object.keys(CONFIG.ALLOWED_HASHES), null, 4);
        txt.value = "<script>\n" +
            "(function(){\n" +
            "  \"use strict\";\n" +
            "  var HUB_URL = \"" + hubUrl + "/\";\n" +
            "  var ALLOWED_HASHES = " + currentHashes + ";\n" +
            "  var SK = \"lks_vault_auth\", SDK = \"lks_vault_auth_date\";\n" +
            "  var s = document.createElement(\"style\");\n" +
            "  s.id = \"lks-lock\"; s.textContent = \"html { visibility: hidden !important; opacity: 0 !important; }\";\n" +
            "  document.documentElement.appendChild(s);\n" +
            "  function unlock() { var el = document.getElementById(\"lks-lock\"); if (el) el.remove(); document.documentElement.style.visibility = \"\"; document.documentElement.style.opacity = \"\"; }\n" +
            "  function doLogout() {\n" +
            "    localStorage.removeItem(SK); localStorage.removeItem(SDK);\n" +
            "    sessionStorage.removeItem(SK);\n" +
            "    document.documentElement.style.visibility = \"hidden\";\n" +
            "    document.documentElement.style.opacity = \"0\";\n" +
            "    var sep = HUB_URL.indexOf(\"?\") >= 0 ? \"&\" : \"?\";\n" +
            "    location.replace(HUB_URL + sep + \"return_url=\" + encodeURIComponent(location.href));\n" +
            "  }\n" +
            "  window.addEventListener(\"message\", function(e){\n" +
            "    if (!e.data || typeof e.data !== \"object\") return;\n" +
            "    if (e.data.type === \"LKS_GUARD_LOGOUT\" || (e.data.type === \"LKS_SESSION_STATUS\" && e.data.valid === false)) doLogout();\n" +
            "  });\n" +
            "  window.addEventListener(\"storage\", function(e){\n" +
            "    if ((e.key === SK && e.newValue !== \"VALID\") || e.key === \"lks_vault_logout_signal\") doLogout();\n" +
            "  });\n" +
            "  async function sha256(t){\n" +
            "    if (!t) return \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\";\n" +
            "    const b = await crypto.subtle.digest(\"SHA-256\", new TextEncoder().encode(t));\n" +
            "    return Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, \"0\")).join(\"\");\n" +
            "  }\n" +
            "  function sessOk(){ return localStorage.getItem(SK) === \"VALID\" && localStorage.getItem(SDK) === new Date().toDateString(); }\n" +
            "  async function verify(){\n" +
            "    var p = new URLSearchParams(location.search);\n" +
            "    if (p.get(\"lks_logout\") === \"1\") {\n" +
            "      p.delete(\"lks_logout\");\n" +
            "      history.replaceState({}, document.title, location.pathname + (p.toString() ? \"?\" + p.toString() : \"\") + location.hash);\n" +
            "      doLogout(); return;\n" +
            "    }\n" +
            "    var auth = p.get(\"auth\");\n" +
            "    var day = new Date().getDate();\n" +
            "    if (auth) {\n" +
            "      for (var i = 0; i < ALLOWED_HASHES.length; i++) {\n" +
            "        var exp = await sha256(ALLOWED_HASHES[i] + \"_\" + day);\n" +
            "        if (auth.toLowerCase() === exp.toLowerCase()) {\n" +
            "          localStorage.setItem(SK, \"VALID\");\n" +
            "          localStorage.setItem(SDK, new Date().toDateString());\n" +
            "          sessionStorage.setItem(SK, \"VALID\");\n" +
            "          p.delete(\"auth\");\n" +
            "          history.replaceState({}, document.title, location.pathname + (p.toString() ? \"?\" + p.toString() : \"\") + location.hash);\n" +
            "          unlock(); return;\n" +
            "        }\n" +
            "      }\n" +
            "    }\n" +
            "    if (sessOk()) { unlock(); return; }\n" +
            "    var sep = HUB_URL.indexOf(\"?\") >= 0 ? \"&\" : \"?\";\n" +
            "    location.replace(HUB_URL + sep + \"return_url=\" + encodeURIComponent(location.href));\n" +
            "  }\n" +
            "  verify();\n" +
            "})();\n" +
            "<\/script>";
    }
}

function openClientCodeModal() {
    var modal = document.getElementById('modalClientCode');
    if (!modal) return;
    var urlInput = document.getElementById("renderHubUrlInput");
    if (urlInput && !urlInput.value) {
        if (window.location && window.location.protocol.startsWith("http")) {
            urlInput.value = window.location.origin;
        } else {
            urlInput.value = "https://twoj-serwis.onrender.com";
        }
    }
    switchClientTab(currentClientTab);
    modal.classList.add('active');
}

function closeClientCodeModal() {
    var modal = document.getElementById('modalClientCode');
    if (modal) modal.classList.remove('active');
}

function copyClientSnippet() {
    var txt = document.getElementById('clientCodeSnippet');
    if (!txt) return;
    txt.select();
    document.execCommand('copy');
    addLog("CLIPBOARD: Skopiowano skrypt klienta (" + currentClientTab.toUpperCase() + ").", "success");
}

// Bindy w oknie globalnym
window.quickFill = quickFill;
window.switchClientTab = switchClientTab;
window.updateClientSnippetView = updateClientSnippetView;
window.openClientCodeModal = openClientCodeModal;
window.closeClientCodeModal = closeClientCodeModal;
window.copyClientSnippet = copyClientSnippet;
window.logout = logout;

// --- INICJALIZACJA ---
window.onload = function () {
    receiveReturnUrl();
    if (window.lucide && typeof window.lucide.createIcons === "function") window.lucide.createIcons();
    setPageLoadActivity("Sprawdzanie zapisu sesji i przygotowanie widoku…", 14);
    var loggedIn = isCurrentlyLoggedIn();
    syncPageLoadSessionLine();
    loadHubGrid();

    if (loggedIn) {
        if (pendingReturnUrl) {
            sendForwardToReturnUrl();
            return;
        }
        showHub();
    } else {
        showAuth();
        if (dom.input) {
            try { dom.input.focus(); } catch (e) { }
        }
    }

    refreshStatusBar();

    setInterval(function () {
        var clock = document.getElementById('sysClock');
        if (clock) clock.textContent = new Date().toLocaleTimeString();
        uptimeSec++;
        var upEl = document.getElementById('uptime');
        if (upEl) upEl.textContent = uptimeSec + "S";
        refreshStatusBar();
    }, 1000);
};

// --- BIND EVENTS ---
var authBtn = document.getElementById('authBtn');
if (authBtn) authBtn.addEventListener('click', handleAuth);

var hubGrid = document.getElementById('hubGrid');
if (hubGrid) {
    hubGrid.addEventListener('click', function (e) {
        var card = e.target.closest('.lks-card');
        if (card && card.getAttribute('data-url')) {
            e.preventDefault();
            connectToNode(card.getAttribute('data-url'));
        }
    });
}

if (dom.input) {
    dom.input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') handleAuth();
    });
    dom.input.addEventListener('input', updateLiveSha);
}

var btnTheme = document.getElementById("themeToggle");
if (btnTheme) btnTheme.addEventListener("click", toggleTheme);

// Blokady systemowe OXY_OS
document.addEventListener("DOMContentLoaded", function () {
    setPageLoadActivity("Ładowanie dokumentu i modułów interfejsu…", 6);
    syncPageLoadSessionLine();
    document.querySelectorAll('[draggable="true"]').forEach(function (el) { el.removeAttribute("draggable"); });
    document.addEventListener("dragstart", function (e) { e.preventDefault(); return false; });
    document.addEventListener("drop", function (e) { e.preventDefault(); return false; });
    document.addEventListener("dragover", function (e) { e.preventDefault(); return false; });
});
