const CONFIG = {
    SECRET: "admin123",
    SESSION_KEY: "lks_vault_auth"
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

function addLog(msg, type = '') {
    const line = document.createElement('div');
    line.className = 'log-line ' + type;
    line.textContent = new Date().toLocaleTimeString() + " :: " + msg;
    dom.terminal.appendChild(line);
    dom.terminal.scrollTop = dom.terminal.scrollHeight;
}

function runBootSequence() {
    let p = 0;
    let lastLogStep = -1;
    const bootLogs = ["Moduły jądra...", "Skanowanie SEC_88...", "Tablica skrótów...", "Gotowość systemowa."];
    const interval = setInterval(function () {
        p += Math.floor(Math.random() * 10) + 5;
        if (p >= 100) {
            p = 100;
            clearInterval(interval);
            dom.progress.style.width = "100%";
            addLog(bootLogs[3] || "Gotowość systemowa.", "success");
            setTimeout(finalizeBoot, 500);
            return;
        }
        dom.progress.style.width = p + "%";
        var step = Math.floor(p / 25);
        if (step > lastLogStep && step < 4) {
            lastLogStep = step;
            addLog(bootLogs[step] || "Przetwarzanie...");
        }
    }, 80);
}

function finalizeBoot() {
    if (sessionStorage.getItem(CONFIG.SESSION_KEY) === "true") {
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

function handleAuth() {
    if (dom.input.value === CONFIG.SECRET) {
        addLog("Autoryzacja OK. Generowanie tokena...", "success");
        sessionStorage.setItem(CONFIG.SESSION_KEY, "true");
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
        window.location.replace(fullUrl);
    }, 400);
}

function logout() {
    sessionStorage.removeItem(CONFIG.SESSION_KEY);
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
    runBootSequence();
    setInterval(function () {
        document.getElementById('sysClock').textContent = new Date().toLocaleTimeString();
        uptimeSec++;
        document.getElementById('uptime').textContent = uptimeSec + "s";
    }, 1000);
};

// Bezpieczne listenery (po załadowaniu DOM)
document.getElementById('authBtn').addEventListener('click', handleAuth);
document.querySelectorAll('.node-card').forEach(function (card) {
    var url = card.getAttribute('data-url');
    if (!url) return;
    card.addEventListener('click', function (e) {
        e.preventDefault();
        connectToNode(url);
    });
});
dom.input.addEventListener('keydown', function (e) { if (e.key === 'Enter') handleAuth(); });
