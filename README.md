# 🛡️ LKS GUARD // RENDER CLOUD AUTHENTICATION

Nowoczesny, bezpieczny hub centralnej autoryzacji dla Twoich stron internetowych (np. **Carrd.co**, GitHub Pages, WordPress, własne domeny), przygotowany do wdrożenia na **[Render.com](https://render.com/)**.

Ochrona stron wyposażona jest w widowiskowy, cyberpunkowy widżet blokady (**LKS Chassis Gate**) z animacją matrycy skanera, telemetrią czasu, zegarem i płynnym paskiem postępu.

---

## 🎨 Wygląd autoryzacji na stronach (LKS Chassis)

Gdy użytkownik wchodzi na chronioną stronę (np. Carrd):
1. **Natychmiastowa blokada**: Cała zawartość strony jest niewidoczna (`visibility: hidden`).
2. **Cyberpunkowy panel weryfikacji**:
   - Wyświetla się panel terminala `LKS_GUARD // SECURITY GATE`.
   - Animowane diody LED skanera (24 bloki matrycy).
   - Telemetria czasu i daty w czasie rzeczywistym.
   - Komunikat `Weryfikacja sesji…`.
3. **Autoryzacja udana (`GUARD // OK`)**:
   - Diody i ramka zmieniają kolor na **zielony** (`#09b83e`).
   - Ikona zamienia się w tarczę z checkmarkiem.
   - Wyświetla się: `ACCESS_GRANTED // SESJA AKTYWNA`.
   - Pasek postępu płynnie dobiega do 100%.
   - Panel płynnie znika, a treść strony staje się w pełni dostępna.
4. **Brak autoryzacji (`GUARD // STOP`)**:
   - Wyświetla się pomarańczowy/czerwony stan błędu.
   - Komunikat: `Brak autoryzacji → Hub` lub `Sesja wygasła → Hub`.
   - Po 1 sekundzie użytkownik zostaje automatycznie przekierowany do bramki logowania Render Hub z parametrem powrotnym (`return_url`). Po wpisaniu hasła wraca bezpośrednio do oglądanej strony.

---

## 🚀 Jak wdrożyć na Render.com

### Krok 1: Wypchnij kod do GitHuba
```powershell
git init
git add .
git commit -m "LKS Guard Render Edition"
git branch -M main
git remote add origin https://github.com/TWOJ_USER/lks-guard.git
git push -u origin main
```

### Krok 2: Utwórz Web Service na Render.com
1. Zaloguj się na [Render.com](https://dashboard.render.com/).
2. Kliknij **New +** -> **Web Service** i wybierz swoje repozytorium.
3. Wybierz:
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: `Free`

### Krok 3: Zmienne środowiskowe (Environment Variables)
- `MASTER_KEY`: Twoje hasło dostępu (tekst lub hash SHA-256).
- `JWT_SECRET`: Dowolny długi ciąg znaków do szyfrowania tokenów.
- `TOKEN_EXPIRES_IN`: np. `24h` lub `7d`.

---

## 💻 Jak wkleić na Carrd.co lub dowolną stronę

Masz do wyboru dwie metody:

### Sposób 1: 1 linijka w sekcji `<head>` lub w elemencie `Embed` (Rekomendowany)
Serwer na Renderze automatycznie serwuje kompletny widżet z animacjami:
```html
<script src="https://twoja-nazwa.onrender.com/api/auth/client.js"></script>
```

### Sposób 2: Pełny kod inline
Możesz skopiować kod z pliku [`client-guard.html`](client-guard.html) lub bezpośrednio z modala **KOD_KLIENTA_STRON** w Hubie (zakładka **RENDER INLINE**).

---

## 📂 Pliki w projekcie

- `server.js` – Serwer Node.js/Express na Render.com (API `/api/auth/login`, `/api/auth/verify`, `/api/auth/client.js`).
- `client-guard.html` – Gotowy podgląd i wzorzec kodu autoryzacji ze stylami i animacją.
- `assets/client-template.js` – Szablon widżetu serwowanego przez `/api/auth/client.js`.
- `index.html` & `index.js` – Główny panel Hub (OXY_OS / LKS Guard).
- `render.yaml` – Konfiguracja Blueprint dla Render.com.
