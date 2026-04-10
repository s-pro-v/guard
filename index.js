const CONFIG = {
    SECRET_ENC: "YWRtaW4xMjM=",
    get SECRET() {
        try { return atob(this.SECRET_ENC); }
        catch (e) { return ""; }
    },
    SESSION_KEY: "lks_vault_auth",
    SESSION_DATE_KEY: "lks_vault_auth_date",
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
        }
    } catch (e) { }
})();

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
    footSessionState: document.getElementById('footSessionState')
};

let hubNodeCount = 0;
var pageLoadingDismissed = false;
var pageLoadingStartedAt = 0;
/** Minimalny czas widoczności nakładki (ms), niezależnie od szybkości fetch. */
var PAGE_LOADING_MIN_MS = 3200;
var PAGE_LOADING_SAFETY_MS = 20000;

function pageLoadingNow() {
    return (typeof performance !== "undefined" && performance.now) ? performance.now() : Date.now();
}

function setPageLoadActivity(msg) {
    var overlay = document.getElementById("pageLoadingOverlay");
    var el = document.getElementById("pageLoadActivity");
    if (!el || !overlay || overlay.classList.contains("lks-page-load--done")) return;
    el.textContent = msg;
}

/** Tekst na nakładce ładowania: sesja zielona = aktualna, czerwona = wymaga ponownej weryfikacji. */
function syncPageLoadSessionLine() {
    var overlay = document.getElementById("pageLoadingOverlay");
    var el = document.getElementById("pageLoadSessionLine");
    if (!el || !overlay || overlay.classList.contains("lks-page-load--done")) return;
    var s = getSessionTokenState();
    el.classList.remove("lks-page-load__session--ok", "lks-page-load__session--bad");
    if (s.kind === "ok") {
        el.classList.add("lks-page-load__session--ok");
        el.textContent = "Sesja LKS jest aktualna (na dziś) — możesz kontynuować po zakończeniu ładowania.";
    } else {
        el.classList.add("lks-page-load__session--bad");
        var bad = {
            expired: "Sesja wygasła — wymagana ponowna weryfikacja kluczem LKS.",
            legacy: "Nieaktualny zapis sesji — wymagana ponowna weryfikacja kluczem LKS.",
            unknown: "Nierozpoznany zapis sesji — wymagana ponowna weryfikacja kluczem LKS.",
            none: "Brak zapisanej sesji — po załadowaniu wymagana weryfikacja kluczem LKS."
        };
        el.textContent = bad[s.kind] || bad.none;
    }
}

function dismissPageLoadingOverlay() {
    if (pageLoadingDismissed) return;
    pageLoadingDismissed = true;
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
    var theme = document.documentElement.getAttribute("theme") || "light";
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
        return false;
    }
    return stored === "VALID" && storedDate === today;
}

/** Stan zapisu w localStorage (bez czyszczenia) — do komunikatów w UI. */
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
            statusText: "SESJA_LKS: AKTUALNA",
            footText: "AKTUALNA",
            title: "Sesja w przeglądarce jest na dziś: zapis VALID i dzisiejsza data. Token do węzłów jest aktualny."
        };
    }
    if (stored === "VALID" && storedDate && storedDate !== today) {
        return {
            kind: "expired",
            statusText: "SESJA_LKS: WYGASŁA",
            footText: "WYGASŁA",
            title: "Data zapisu (" + storedDate + ") nie jest dzisiejsza. Zaloguj się ponownie kluczem LKS."
        };
    }
    if (stored === "true") {
        return {
            kind: "legacy",
            statusText: "SESJA_LKS: STARY_ZAPIS",
            footText: "STARY_ZAPIS",
            title: "Stary format zapisu sesji. Zalecane ponowne logowanie, aby uzyskać pełny zapis VALID z datą."
        };
    }
    if (stored) {
        return {
            kind: "unknown",
            statusText: "SESJA_LKS: NIEZNANA",
            footText: "NIEZNANA",
            title: "Nierozpoznany zapis klucza sesji. Wyczyść dane witryny lub zaloguj się ponownie."
        };
    }
    return {
        kind: "none",
        statusText: "SESJA_LKS: BRAK",
        footText: "BRAK",
        title: "Brak zapisanej sesji LKS w tej przeglądarce."
    };
}

function applySessionValidityToDom(s) {
    var kinds = ["ok", "expired", "legacy", "none", "unknown"];
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

function getAuthToken() {
    return btoa(CONFIG.SECRET + "_" + new Date().getDate());
}

function receiveReturnUrl() {
    var params = new URLSearchParams(window.location.search);
    var returnUrl = params.get("return_url");
    if (returnUrl) {
        try {
            sessionStorage.setItem(CONFIG.RETURN_URL_KEY, returnUrl);
            var clean = window.location.protocol + "//" + window.location.host + window.location.pathname;
            var rest = [];
            params.forEach(function (val, key) {
                if (key !== "return_url") rest.push(key + "=" + encodeURIComponent(val));
            });
            if (rest.length) clean += "?" + rest.join("&");
            window.history.replaceState({}, document.title, clean);
        } catch (e) { }
    }
}

function sendForwardToReturnUrl() {
    var returnUrl = sessionStorage.getItem(CONFIG.RETURN_URL_KEY);
    if (!returnUrl) return false;
    sessionStorage.removeItem(CONFIG.RETURN_URL_KEY);
    var sep = returnUrl.indexOf("?") >= 0 ? "&" : "?";
    var target = returnUrl + sep + "auth=" + encodeURIComponent(getAuthToken());
    window.location.replace(target);
    return true;
}

function getFaviconUrl(url) {
    var cleanUrl = url.replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
    if (cleanUrl.indexOf("carrd.co") !== -1) {
        return "https://" + cleanUrl + "/assets/images/favicon.png";
    }
    return "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://" + cleanUrl + "&size=32";
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

    if (isCarrd) {
        if (attempt === 1) {
            imgElement.src = "https://" + cleanUrl + "/assets/images/apple-touch-icon.png";
            imgElement.dataset.attempt = "2";
        } else if (attempt === 2) {
            imgElement.src = "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://" + cleanUrl + "&size=32";
            imgElement.dataset.attempt = "3";
        } else {
            showFaviconFallback(imgElement);
        }
    } else {
        if (attempt === 1) {
            imgElement.src = "https://www.google.com/s2/favicons?domain=" + cleanUrl + "&sz=32";
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

var DEFAULT_CARDS = [];

var CARD_BODY_IMAGES = {
    "editor-vs.carrd.co": "https://editor-vs.carrd.co/assets/images/share.jpg?v=1acb2340",
    "vs-note.carrd.co": "https://vs-note.carrd.co/assets/images/share.jpg?v=97ba449d",
    "previewgib.carrd.co": "https://previewgib.carrd.co/assets/images/share.jpg?v=0d5dac00",
    "grafikdev.carrd.co": "https://grafikdev.carrd.co/assets/images/share.jpg?v=63294947",
    "devospanel.carrd.co": "https://devospanel.carrd.co/assets/images/share.jpg?v=e72d9232",
    "linkosi.carrd.co": "https://linkosi.carrd.co/assets/images/share.jpg?v=4271e371"
};
var DEFAULT_CARD_BODY_IMAGE = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100'%3E%3Crect width='100' height='100' fill='%23181818'/%3E%3Cpath d='M0 100 L100 0' stroke='%23333' stroke-width='1'/%3E%3C/svg%3E";

function getCardDomain(url) {
    return (url || "").replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
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

        var domain = getCardDomain(url);
        var bodyBg = cardImage || (CARD_BODY_IMAGES[domain] || DEFAULT_CARD_BODY_IMAGE);

        a.innerHTML =
            "<div class=\"lks-card__head\">" +
            "<div class=\"lks-card__favicon\">" +
            "<img class=\"lks-card__favicon-img\" alt=\"\" />" +
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

function escapeHtml(text) {
    var div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

function loadHubGrid() {
    var url = CONFIG.CARDS_URL;
    pageLoadingStartedAt = pageLoadingNow();
    setPageLoadActivity("Pobieranie katalogu kart z repozytorium…");
    syncPageLoadSessionLine();
    var safety = setTimeout(dismissPageLoadingOverlay, PAGE_LOADING_SAFETY_MS);
    fetch(url)
        .then(function (res) {
            setPageLoadActivity("Walidacja odpowiedzi serwera i odczyt listy…");
            return res.ok ? res.json() : Promise.reject(new Error(res.status));
        })
        .then(function (data) {
            setPageLoadActivity("Budowa siatki punktów wejścia…");
            var cards = Array.isArray(data) ? data : (data.cards || data.items || []);
            renderHubGrid(cards);
        })
        .catch(function () {
            setPageLoadActivity("Błąd sieci — odtwarzanie lokalnej listy kart…");
            renderHubGrid(DEFAULT_CARDS);
            if (dom.terminal) addLog("FETCH_ERROR: Odtwarzanie listy lokalnej przerwane. Brak card.json.", "warning");
        })
        .finally(function () {
            setPageLoadActivity("Kończenie inicjalizacji interfejsu…");
            syncPageLoadSessionLine();
            clearTimeout(safety);
            var elapsed = pageLoadingNow() - pageLoadingStartedAt;
            var wait = Math.max(0, PAGE_LOADING_MIN_MS - elapsed);
            setTimeout(dismissPageLoadingOverlay, wait);
        });
}

function addLog(msg, type = '') {
    const line = document.createElement('div');
    line.className = 'lks-log__line ' + type;
    const time = new Date().toISOString().split('T')[1].slice(0, -1);
    line.textContent = time + " :: " + msg;
    dom.terminal.appendChild(line);
    dom.terminal.scrollTop = dom.terminal.scrollHeight;
}

function showAuth() {
    setAppPhase(1);
    dom.auth.classList.add('active');
    addLog("SYS.BOOT: Oczekiwanie na klucz szyfrujący OXY_OS...", "warning");
}

function showHub() {
    setAppPhase(2);
    dom.auth.classList.remove('active');
    dom.hub.classList.add('active');
    dom.lvl.textContent = "2_ADMIN";
    dom.lvl.classList.remove("lks-footbar__auth--guest");
    dom.lvl.classList.add("lks-footbar__auth--admin");
    addLog("AUTH.SUCCESS: Ustanowiono bezpieczne połączenie węzłów.", "success");
}

function checkKeyMatch(raw) {
    var s = (raw || "").trim();
    if (!s) return false;
    if (s === CONFIG.SECRET) return true;
    try { if (atob(s) === CONFIG.SECRET) return true; } catch (e) { }
    return false;
}

function handleAuth() {
    if (checkKeyMatch(dom.input.value)) {
        addLog("VALIDATING_KEY: OK. Odszyfrowywanie...", "success");
        localStorage.setItem(CONFIG.SESSION_KEY, "VALID");
        localStorage.setItem(CONFIG.SESSION_DATE_KEY, new Date().toDateString());
        if (sendForwardToReturnUrl()) return;
        setTimeout(showHub, 600);
    } else {
        addLog("ERR_ACCESS_DENIED: Niewłaściwy wektor inicjalizacyjny!", "danger");
        dom.input.value = "";
        const container = document.getElementById('mainContainer');
        container.classList.add("lks-frame--access-denied");
        if (dom.statusBarMode) dom.statusBarMode.textContent = "SESJA: ODMOWA_DOSTĘPU";
        if (dom.statusBarLed) {
            dom.statusBarLed.classList.remove("lks-statusbar__led--hub");
            dom.statusBarLed.classList.add("lks-statusbar__led--denied");
        }
        setTimeout(function () {
            container.classList.remove("lks-frame--access-denied");
            refreshStatusBar();
        }, 400);
    }
}

function connectToNode(url) {
    if (!url) return;
    url = url.replace(/\/$/, "");
    const token = getAuthToken();
    addLog("HANDSHAKE_INIT → " + url, "success");
    const fullUrl = url + (url.indexOf("?") >= 0 ? "&" : "?") + "auth=" + encodeURIComponent(token);
    setTimeout(function () { window.open(fullUrl, "_blank", "noopener,noreferrer"); }, 400);
}

function toggleTheme() {
    var root = document.documentElement;
    var cur = root.getAttribute("theme") || "light";
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
    addLog("SYS.LOGOUT: Czyszczenie pamięci podręcznej i tokenów...", "warning");

    var firstCard = document.querySelector(".lks-card[data-url]");
    var cardUrl = firstCard ? (firstCard.getAttribute("data-url") || "").trim() : "";

    setTimeout(() => {
        if (cardUrl) {
            var sep = cardUrl.indexOf("?") >= 0 ? "&" : "?";
            window.location.href = cardUrl + sep + CONFIG.LOGOUT_PARAM;
        } else {
            location.reload();
        }
    }, 500);
}

window.onload = function () {
    receiveReturnUrl();
    if (window.lucide && typeof window.lucide.createIcons === "function") window.lucide.createIcons();
    setPageLoadActivity("Sprawdzanie zapisu sesji i przygotowanie widoku…");
    var loggedIn = isCurrentlyLoggedIn() || localStorage.getItem(CONFIG.SESSION_KEY) === "true";
    syncPageLoadSessionLine();
    loadHubGrid();

    if (loggedIn) {
        showHub();
        setTimeout(function () {
            if (sendForwardToReturnUrl()) return;
        }, 100);
    } else {
        showAuth();
        if (dom.input) {
            try { dom.input.focus(); } catch (e) { }
        }
    }

    refreshStatusBar();

    setInterval(function () {
        document.getElementById('sysClock').textContent = new Date().toLocaleTimeString();
        uptimeSec++;
        document.getElementById('uptime').textContent = uptimeSec + "S";
        refreshStatusBar();
    }, 1000);
};

// --- BIND EVENTS ---
document.getElementById('authBtn').addEventListener('click', handleAuth);

document.getElementById('hubGrid').addEventListener('click', function (e) {
    var card = e.target.closest('.lks-card');
    if (card && card.getAttribute('data-url')) {
        e.preventDefault();
        connectToNode(card.getAttribute('data-url'));
    }
});

dom.input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') handleAuth();
});

(function bindThemeToggle() {
    var btn = document.getElementById("themeToggle");
    if (btn) btn.addEventListener("click", toggleTheme);
})();

// Blokady systemowe OXY_OS
document.addEventListener("DOMContentLoaded", function () {
    setPageLoadActivity("Ładowanie dokumentu i modułów interfejsu…");
    syncPageLoadSessionLine();
    document.querySelectorAll('[draggable="true"]').forEach((el) => { el.removeAttribute("draggable"); });
    document.addEventListener("dragstart", function (e) { e.preventDefault(); return false; });
    document.addEventListener("drop", function (e) { e.preventDefault(); return false; });
    document.addEventListener("dragover", function (e) { e.preventDefault(); return false; });
});