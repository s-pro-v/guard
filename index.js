const CONFIG = {
    SECRET_ENC: "YWRtaW4xMjM=",
    get SECRET() {
        try {
            return atob(this.SECRET_ENC);
        } catch (e) {
            return "";
        }
    },
    SESSION_KEY: "lks_vault_auth",
    CARDS_URL: "https://raw.githubusercontent.com/s-pro-v/json-lista/refs/heads/main/card.json"
};

const dom = {
    boot: document.getElementById('bootScreen'),
    auth: document.getElementById('authView'),
    hub: document.getElementById('hubView'),
    input: document.getElementById('passInput'),
    terminal: document.getElementById('terminal'),
    progress: document.getElementById('bootProgress'),
    lvl: document.getElementById('authLvl')
};

let uptimeSec = 0;

// --- Favicon dla kart hub (ikony według stron) ---
function getFaviconUrl(url) {
    var cleanUrl = url
        .replace(/^https?:\/\//, "")
        .replace(/^www\./, "")
        .split("/")[0];
    if (cleanUrl.indexOf("carrd.co") !== -1) {
        return "https://" + cleanUrl + "/assets/images/favicon.png";
    }
    return "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://" + cleanUrl + "&size=32";
}

function getFirstLetter(url) {
    try {
        var domain = url
            .replace(/^https?:\/\//, "")
            .replace(/^www\./, "");
        return domain.charAt(0).toUpperCase();
    } catch (e) {
        return "?";
    }
}

function handleFaviconError(imgElement, url) {
    var attempt = parseInt(imgElement.dataset.attempt, 10) || 1;
    var cleanUrl = url
        .replace(/^https?:\/\//, "")
        .replace(/^www\./, "")
        .split("/")[0];
    var isCarrd = cleanUrl.indexOf("carrd.co") !== -1;

    if (isCarrd) {
        if (attempt === 1) {
            imgElement.src = "https://" + cleanUrl + "/assets/images/apple-touch-icon.png";
            imgElement.dataset.attempt = "2";
        } else if (attempt === 2) {
            imgElement.src = "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://" + cleanUrl + "&size=32";
            imgElement.dataset.attempt = "3";
        } else if (attempt === 3) {
            imgElement.src = "https://favicon.yandex.net/favicon/" + cleanUrl;
            imgElement.dataset.attempt = "4";
        } else {
            showFaviconFallback(imgElement);
        }
    } else {
        if (attempt === 1) {
            imgElement.src = "https://www.google.com/s2/favicons?domain=" + cleanUrl + "&sz=32";
            imgElement.dataset.attempt = "2";
        } else if (attempt === 2) {
            imgElement.src = "https://icons.duckduckgo.com/ip3/" + cleanUrl + ".ico";
            imgElement.dataset.attempt = "3";
        } else if (attempt === 3) {
            imgElement.src = "https://" + cleanUrl + "/favicon.ico";
            imgElement.dataset.attempt = "4";
        } else {
            showFaviconFallback(imgElement);
        }
    }
}

function showFaviconFallback(imgElement) {
    imgElement.style.display = "none";
    var fallback = imgElement.nextElementSibling;
    if (fallback && fallback.classList.contains("node-card-favicon-fallback")) {
        fallback.style.display = "flex";
    }
}

function loadFaviconsForHub() {
    document.querySelectorAll(".node-card").forEach(function (card) {
        var url = card.getAttribute("data-url") || card.getAttribute("href");
        if (!url) return;
        var wrap = card.querySelector(".node-card-favicon-wrap");
        if (!wrap) return;
        var img = wrap.querySelector(".node-card-favicon");
        var fallbackSpan = wrap.querySelector(".node-card-favicon-fallback");
        if (!img || !fallbackSpan) return;
        fallbackSpan.textContent = getFirstLetter(url);
        img.dataset.attempt = "1";
        img.src = getFaviconUrl(url);
        img.onerror = function () {
            handleFaviconError(img, url);
        };
    });
}

var DEFAULT_CARDS = [

];

// Obrazek share.jpg dla .node-card-body według domeny karty
var CARD_BODY_IMAGES = {
    "editor-vs.carrd.co": "https://editor-vs.carrd.co/assets/images/share.jpg?v=1acb2340",
    "vs-note.carrd.co": "https://vs-note.carrd.co/assets/images/share.jpg?v=97ba449d",
    "previewgib.carrd.co": "https://previewgib.carrd.co/assets/images/share.jpg?v=0d5dac00",
    "grafikdev.carrd.co": "https://grafikdev.carrd.co/assets/images/share.jpg?v=63294947",
    "devospanel.carrd.co": "https://devospanel.carrd.co/assets/images/share.jpg?v=e72d9232",
    "linkosi.carrd.co": "https://linkosi.carrd.co/assets/images/share.jpg?v=4271e371"
};


function getCardDomain(url) {
    return (url || "").replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
}

function renderHubGrid(cards) {
    var grid = document.getElementById("hubGrid");
    if (!grid) return;
    grid.innerHTML = "";
    if (!Array.isArray(cards) || cards.length === 0) return;
    cards.forEach(function (item) {
        var url = (item.url || item.href || "").trim();
        var title = item.title || "Node";
        var description = item.description || item.desc || "";
        var cardImage = (item.image || item.img || "").trim();
        if (!url) return;
        var a = document.createElement("a");
        a.className = "node-card";
        a.href = url;
        a.setAttribute("data-url", url);
        var bodyImg = cardImage
            ? "<div class=\"node-card-image-wrap\"><img class=\"node-card-image\" src=\"" + cardImage.replace(/"/g, "&quot;") + "\" alt=\"\" /></div>"
            : "";
        var domain = getCardDomain(url);
        var bodyBg = cardImage || (CARD_BODY_IMAGES[domain] || DEFAULT_CARD_BODY_IMAGE);
        a.innerHTML =
            "<div class=\"node-card-header\">" +
            "<span class=\"node-card-favicon-wrap\">" +
            "<img class=\"node-card-favicon\" alt=\"\" />" +
            "<span class=\"node-card-favicon-fallback\"></span>" +
            "</span>" +
            "<h3>" + escapeHtml(title) + "</h3>" +
            "</div>" +
            "<div class=\"node-card-body\">" + bodyImg + "<p>" + escapeHtml(description) + "</p></div>";
        grid.appendChild(a);
        a.querySelector(".node-card-body").style.backgroundImage = "url(\"" + bodyBg.replace(/"/g, "\\\"") + "\")";
    });
    loadFaviconsForHub();
}

function escapeHtml(text) {
    var div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

function loadHubGrid() {
    var url = CONFIG.CARDS_URL;
    fetch(url)
        .then(function (res) { return res.ok ? res.json() : Promise.reject(new Error(res.status)); })
        .then(function (data) {
            var cards = Array.isArray(data) ? data : (data.cards || data.items || []);
            renderHubGrid(cards);
        })
        .catch(function () {
            renderHubGrid(DEFAULT_CARDS);
            if (dom.terminal) addLog("Hub: używam listy lokalnej (card.json niedostępny).", "warning");
        });
}

function addLog(msg, type = '') {
    const line = document.createElement('div');
    line.className = 'log-line ' + type;
    line.textContent = new Date().toLocaleTimeString() + " :: " + msg;
    dom.terminal.appendChild(line);
    dom.terminal.scrollTop = dom.terminal.scrollHeight;
}

function runBootSequence() {
    var p = 0;
    var lastLogStep = 0;
    var bootLogs = ["Moduły jądra...", "Skanowanie SEC_88...", "Tablica skrótów...", "Gotowość systemowa."];
    var milestones = [25, 50, 75, 100];
    var interval = setInterval(function () {
        p += Math.floor(Math.random() * 2) + 1;
        if (p >= 100) {
            p = 100;
            clearInterval(interval);
            dom.progress.style.width = "100%";
            dom.progress.classList.add("complete");
            addLog(bootLogs[3], "success");
            setTimeout(finalizeBoot, 500);
            return;
        }
        dom.progress.style.width = p + "%";
        for (var i = lastLogStep; i < milestones.length; i++) {
            if (p >= milestones[i]) {
                addLog(bootLogs[i], i === 3 ? "success" : "");
                lastLogStep = i + 1;
            }
        }
    }, 50);
}

function finalizeBoot() {
    if (localStorage.getItem(CONFIG.SESSION_KEY) === "true") {
        showHub();
    } else {
        showAuth();
    }
}

function showAuth() {
    dom.boot.classList.remove('active');
    dom.auth.classList.add('active');
    addLog("Oczekiwanie na klucz...", "warning");
}

function showHub() {
    dom.boot.classList.remove('active');
    dom.auth.classList.remove('active');
    dom.hub.classList.add('active');
    dom.lvl.textContent = "2_ADMIN";
    dom.lvl.style.color = "var(--success-color)";
    addLog("SESJA_AKTYWNA: Węzły odblokowane.", "success");
}

function checkKeyMatch(raw) {
    var s = (raw || "").trim();
    if (!s) return false;
    if (s === CONFIG.SECRET) return true;
    try {
        if (atob(s) === CONFIG.SECRET) return true;
    } catch (e) { }
    return false;
}

function handleAuth() {
    if (checkKeyMatch(dom.input.value)) {
        addLog("Autoryzacja OK. Generowanie tokena...", "success");
        localStorage.setItem(CONFIG.SESSION_KEY, "true");
        setTimeout(showHub, 600);
    } else {
        addLog("BŁĄD: Nieprawidłowy klucz!", "danger");
        dom.input.value = "";
        const container = document.querySelector('.system-container');
        container.style.borderColor = "var(--danger-color)";
        setTimeout(function () { container.style.borderColor = "var(--border-color)"; }, 400);
    }
}

function connectToNode(url) {
    if (!url) return;
    url = url.replace(/\/$/, ""); // bez końcowego slasha
    const token = btoa(CONFIG.SECRET + "_" + new Date().getDate());
    addLog("Inicjalizacja Handshake → " + url, "success");
    const fullUrl = url + (url.indexOf("?") >= 0 ? "&" : "?") + "auth=" + encodeURIComponent(token);
    setTimeout(function () {
        window.open(fullUrl, "_blank", "noopener,noreferrer");
    }, 400);
}

function logout() {
    localStorage.removeItem(CONFIG.SESSION_KEY);
    location.reload();
}

function toggleTheme() {
    const root = document.documentElement;
    const next = root.getAttribute('theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('theme', next);
    localStorage.setItem('lks_theme', next);
    addLog("Zmiana motywu: " + next.toUpperCase());
}

window.onload = function () {
    const saved = localStorage.getItem('lks_theme') || 'dark';
    document.documentElement.setAttribute('theme', saved);
    if (window.lucide && typeof window.lucide.createIcons === "function") window.lucide.createIcons();
    loadHubGrid();
    runBootSequence();
    setInterval(function () {
        document.getElementById('sysClock').textContent = new Date().toLocaleTimeString();
        uptimeSec++;
        document.getElementById('uptime').textContent = uptimeSec + "s";
    }, 1000);
};

// Bezpieczne listenery (po załadowaniu DOM)
document.getElementById('authBtn').addEventListener('click', handleAuth);
document.getElementById('hubGrid').addEventListener('click', function (e) {
    var card = e.target.closest('.node-card');
    if (card && card.getAttribute('data-url')) {
        e.preventDefault();
        connectToNode(card.getAttribute('data-url'));
    }
});
dom.input.addEventListener('keydown', function (e) { if (e.key === 'Enter') handleAuth(); });

// Add these to your existing script section
document.addEventListener("DOMContentLoaded", function () {
    // Remove draggable attribute from all elements
    document.querySelectorAll('[draggable="true"]').forEach((el) => {
        el.removeAttribute("draggable");
    });

    // Prevent dragstart event
    document.addEventListener("dragstart", function (e) {
        e.preventDefault();
        return false;
    });

    // Prevent drop event
    document.addEventListener("drop", function (e) {
        e.preventDefault();
        return false;
    });

    // Prevent dragover event
    document.addEventListener("dragover", function (e) {
        e.preventDefault();
        return false;
    });
});
