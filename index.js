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

function receiveReturnUrl() {
    var params = new URLSearchParams(window.location.search);
    var returnUrl = params.get("return_url") || params.get("redirect") || params.get("r");
    
    // Jeśli nie ma w parametrach URL, sprawdź pamięć sesji
    if (!returnUrl) {
        try {
            returnUrl = sessionStorage.getItem(CONFIG.RETURN_URL_KEY) || localStorage.getItem(CONFIG.RETURN_URL_KEY);
        } catch(e) {}
    }
    
    // Jeśli nadal brak, sprawdź czy użytkownik przyszedł z innej domeny (document.referrer)
    if (!returnUrl && document.referrer) {
        try {
            var refUrl = new URL(document.referrer);
            if (refUrl.host !== window.location.host) {
                returnUrl = document.referrer;
            }
        } catch(e) {}
    }

    if (returnUrl) {
        pendingReturnUrl = returnUrl;
        try {
            sessionStorage.setItem(CONFIG.RETURN_URL_KEY, returnUrl);
            localStorage.setItem(CONFIG.RETURN_URL_KEY, returnUrl);
        } catch (e) { }

        var banner = document.getElementById("returnBanner");
        var bannerText = document.getElementById("returnUrlText");
        if (banner && bannerText) {
            bannerText.textContent = returnUrl;
            banner.style.display = "flex";
        }

        var authSubmitBtn = document.getElementById("authBtn");
        if (authSubmitBtn) {
            authSubmitBtn.innerHTML = '<i data-lucide="corner-down-right" class="lks-icon" aria-hidden="true"></i> AUTORYZUJ I PRZEJDŹ DO STRONY';
            if (window.lucide && typeof window.lucide.createIcons === "function") window.lucide.createIcons();
        }
    }
}

async function sendForwardToReturnUrl(hashUsed) {
    var returnUrl = pendingReturnUrl;
    if (!returnUrl) {
        try {
            returnUrl = sessionStorage.getItem(CONFIG.RETURN_URL_KEY) || localStorage.getItem(CONFIG.RETURN_URL_KEY);
        } catch(e) {}
    }
    if (!returnUrl) return false;

    pendingReturnUrl = null;
    try {
        sessionStorage.removeItem(CONFIG.RETURN_URL_KEY);
        localStorage.removeItem(CONFIG.RETURN_URL_KEY);
    } catch(e) {}

    addLog("REDIRECT: Przekierowanie do strony wywołującej: " + returnUrl, "success");
    var token = await getShaAuthToken(hashUsed);
    var sep = returnUrl.indexOf("?") >= 0 ? "&" : "?";
    var target = returnUrl + sep + "auth=" + encodeURIComponent(token);
    
    setTimeout(function () {
        window.location.href = target;
    }, 200);
    return true;
}

async function handleAuth() {
    var raw = (dom.input ? dom.input.value : "").trim();
    if (!raw) {
        addLog("ERR_AUTH: Proszę wprowadzić wektor inicjalizacyjny!", "danger");
        return;
    }

    var inputHash = await computeSha256(raw);
    var role = CONFIG.ALLOWED_HASHES[inputHash];

    if (role) {
        addLog(`AUTH_SUCCESS: Klucz poprawny. Rola: [${role}]. Suma SHA-256 zweryfikowana.`, "success");
        localStorage.setItem(CONFIG.SESSION_KEY, "VALID");
        localStorage.setItem(CONFIG.SESSION_DATE_KEY, new Date().toDateString());
        localStorage.setItem(CONFIG.SESSION_HASH_KEY, inputHash);

        var hasRedirected = await sendForwardToReturnUrl(inputHash);
        if (hasRedirected) return;

        setTimeout(showHub, 500);
    } else {
        addLog("ERR_ACCESS_DENIED: Niezgodność sumy kontrolnej SHA-256!", "danger");
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
    addLog("SYS.BOOT: Oczekiwanie na identyfikację kryptograficzną SHA-256...", "warning");
}

function showHub() {
    setAppPhase(2);
    if (dom.auth) dom.auth.classList.remove('active');
    if (dom.hub) dom.hub.classList.add('active');
    var storedHash = localStorage.getItem(CONFIG.SESSION_HASH_KEY);
    var role = CONFIG.ALLOWED_HASHES[storedHash] || "2_ADMIN";
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
    var token = await getShaAuthToken();
    addLog("HANDSHAKE_SHA256 → " + url, "success");
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
            imgElement.src = "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://" + cleanUrl + "&size=32&v=" + ver;
            imgElement.dataset.attempt = "3";
        } else {
            showFaviconFallback(imgElement);
        }
    } else {
        if (attempt === 1) {
            imgElement.src = "https://www.google.com/s2/favicons?domain=" + cleanUrl + "&sz=32&v=" + ver;
            imgElement.dataset.attempt = "2";
        } else {
            showFaviconFallback(imgElement);
        }
    }
}

function showFaviconFallback(imgElement) {
    imgElement.style.display = "none";
    var fallback = imgElement.nextElementSibling;
    if (fallback && fallback.classList.contains("lks-card__favicon-fallback")) {
        fallback.style.display = "block";
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
        var cardImage = (item.image || item.img || "").trim();
        if (!url) return;
        hubNodeCount++;

        var a = document.createElement("a");
        a.className = "lks-card";
        a.href = url;
        a.setAttribute("data-url", url);

        var bodyBg = cardImage || "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100'%3E%3Crect width='100' height='100' fill='%23181818'/%3E%3Cpath d='M0 100 L100 0' stroke='%23333' stroke-width='1'/%3E%3C/svg%3E";

        a.innerHTML =
            "<div class=\"lks-card__head\">" +
            "<div class=\"lks-card__favicon\">" +
            "<img class=\"lks-card__favicon-img\" alt=\"\" src=\"" + getFaviconUrl(url) + "\" />" +
            "<span class=\"lks-card__favicon-fallback\"></span>" +
            "</div>" +
            "<h3>" + escapeHtml(title) + "</h3>" +
            "</div>" +
            "<div class=\"lks-card__media\" style=\"background-image: url('" + bodyBg.replace(/'/g, "\\'") + "');\"></div>" +
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

// MODAL KODU KLIENTA DLA STRON (LKS GUARD)
function openClientCodeModal() {
    var modal = document.getElementById('modalClientCode');
    if (!modal) return;
    var txt = document.getElementById('clientCodeSnippet');

    var currentHashes = JSON.stringify(Object.keys(CONFIG.ALLOWED_HASHES), null, 4);

    var clientJs = `<script>\n` +
        `(function(){\n` +
        `  "use strict";\n` +
        `  var HUB_URL = "https://s-pro-v.github.io/guard/";\n` +
        `  var ALLOWED_HASHES = ` + currentHashes + `;\n` +
        `  var SK = "lks_vault_auth", SDK = "lks_vault_auth_date";\n` +
        `  \n` +
        `  // Blokada widoku strony przed autoryzacją\n` +
        `  var s = document.createElement("style");\n` +
        `  s.id = "lks-lock"; s.textContent = "html { visibility: hidden !important; opacity: 0 !important; }";\n` +
        `  document.documentElement.appendChild(s);\n` +
        `  function unlock() { var el = document.getElementById("lks-lock"); if (el) el.remove(); document.documentElement.style.visibility = ""; document.documentElement.style.opacity = ""; }\n` +
        `  \n` +
        `  function doLogout() {\n` +
        `    localStorage.removeItem(SK); localStorage.removeItem(SDK);\n` +
        `    sessionStorage.removeItem(SK);\n` +
        `    document.documentElement.style.visibility = "hidden";\n` +
        `    document.documentElement.style.opacity = "0";\n` +
        `    location.replace(HUB_URL);\n` +
        `  }\n` +
        `  \n` +
        `  // 1. Odbiór sygnału wylogowania z Huba (postMessage)\n` +
        `  window.addEventListener("message", function(e){\n` +
        `    if (!e.data || typeof e.data !== "object") return;\n` +
        `    if (e.data.type === "LKS_GUARD_LOGOUT" || (e.data.type === "LKS_SESSION_STATUS" && !e.data.valid)) {\n` +
        `      doLogout();\n` +
        `    }\n` +
        `  });\n` +
        `  \n` +
        `  // 2. Wykrywanie wylogowania w tej samej domenie (zdarzenie storage)\n` +
        `  window.addEventListener("storage", function(e){\n` +
        `    if ((e.key === SK && e.newValue !== "VALID") || e.key === "lks_vault_logout_signal") {\n` +
        `      doLogout();\n` +
        `    }\n` +
        `  });\n` +
        `  \n` +
        `  // 3. Ciągły Heartbeat - sprawdzanie czy Hub jest nadal zalogowany\n` +
        `  function checkHubSession() {\n` +
        `    if (!window.opener || window.opener.closed) {\n` +
        `      doLogout();\n` +
        `      return;\n` +
        `    }\n` +
        `    try {\n` +
        `      window.opener.postMessage({ type: "LKS_SESSION_CHECK" }, "*");\n` +
        `    } catch(e) {}\n` +
        `  }\n` +
        `  \n` +
        `  window.addEventListener("focus", checkHubSession);\n` +
        `  document.addEventListener("visibilitychange", function(){\n` +
        `    if (document.visibilityState === "visible") checkHubSession();\n` +
        `  });\n` +
        `  setInterval(checkHubSession, 1500);\n` +
        `  \n` +
        `  async function sha256(t){\n` +
        `    if (!t) return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";\n` +
        `    const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t));\n` +
        `    return Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, "0")).join("");\n` +
        `  }\n` +
        `  function sessOk(){ return localStorage.getItem(SK) === "VALID" && localStorage.getItem(SDK) === new Date().toDateString(); }\n` +
        `  \n` +
        `  async function verify(){\n` +
        `    var p = new URLSearchParams(location.search);\n` +
        `    if (p.get("lks_logout") === "1") { doLogout(); return; }\n` +
        `    var auth = p.get("auth");\n` +
        `    var day = new Date().getDate();\n` +
        `    if (auth) {\n` +
        `      for (var i = 0; i < ALLOWED_HASHES.length; i++) {\n` +
        `        var exp = await sha256(ALLOWED_HASHES[i] + "_" + day);\n` +
        `        if (auth.toLowerCase() === exp.toLowerCase()) {\n` +
        `          localStorage.setItem(SK, "VALID");\n` +
        `          localStorage.setItem(SDK, new Date().toDateString());\n` +
        `          p.delete("auth");\n` +
        `          var clean = location.pathname + (p.toString() ? "?" + p.toString() : "") + location.hash;\n` +
        `          history.replaceState({}, document.title, clean);\n` +
        `          unlock();\n` +
        `          checkHubSession();\n` +
        `          return;\n` +
        `        }\n` +
        `      }\n` +
        `    }\n` +
        `    if (sessOk()) {\n` +
        `      if (window.opener && !window.opener.closed) {\n` +
        `        unlock();\n` +
        `        checkHubSession();\n` +
        `        return;\n` +
        `      }\n` +
        `    }\n` +
        `    var sep = HUB_URL.indexOf("?") >= 0 ? "&" : "?";\n` +
        `    location.replace(HUB_URL + sep + "return_url=" + encodeURIComponent(location.href));\n` +
        `  }\n` +
        `  verify();\n` +
        `})();\n` +
        `<\/script>`;

    if (txt) txt.value = clientJs;
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
    addLog("CLIPBOARD: Skopiowano skrypt klienta SHA-256.", "success");
}

// Bindy w oknie globalnym
window.quickFill = quickFill;
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
        if (pendingReturnUrl || sessionStorage.getItem(CONFIG.RETURN_URL_KEY) || localStorage.getItem(CONFIG.RETURN_URL_KEY)) {
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
