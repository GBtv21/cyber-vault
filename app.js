// ============================================================
//  CYBERVAULT — LOGICA DELL'APPLICAZIONE
//  Gestisce le schermate e lo stato del vault.
//  REGOLA D'ORO: la master password esiste SOLO in memoria,
//  finché la pagina è aperta. Non viene MAI salvata.
// ============================================================

let vaultKey = null;          // la master password, in memoria RAM soltanto
let entries = [];             // le entry decifrate, in memoria
const STORAGE_KEY = 'cybervault_file'; // dove si trova il file cifrato

// ------------------------------------------------------------
// AVVIO: il vault esiste già (localStorage) o è la prima volta?
// ------------------------------------------------------------
function init() {
  const existing = localStorage.getItem(STORAGE_KEY);
  document.getElementById('unlockHint').textContent = existing
    ? 'Vault trovato. Inserisci la tua master password per aprirlo.'
    : 'Prima volta? Scegli una master password FORTE: sarà l’unica che dovrai ricordare.';
}

// ------------------------------------------------------------
// APERTURA / CREAZIONE DEL VAULT
// La stessa funzione gestisce entrambi i casi: se il vault
// esiste, decrypt fallirà con la password sbagliata (e noi
// lo segnaliamo). Se non esiste, lo creiamo vuoto.
// ------------------------------------------------------------
async function unlock() {
  const pwd = document.getElementById('masterPassword').value;
  const errorEl = document.getElementById('unlockError');
  errorEl.textContent = '';

  if (pwd.length < 8) {
    errorEl.textContent = 'La master password deve avere almeno 8 caratteri.';
    return;
  }

  try {
    const saved = localStorage.getItem(STORAGE_KEY);

    if (saved) {
      // Vault esistente: proviamo a decifrarlo
      const plainText = await decryptVault(JSON.parse(saved), pwd);
      entries = JSON.parse(plainText);
    } else {
      // Primo avvio: vault vuoto
      entries = [];
      await saveVault(pwd); // subito! così il file cifrato esiste già
    }

    vaultKey = pwd;
    showVaultScreen();
  } catch (e) {
    // AES-GCM ha rilevato: password sbagliata O file manomesso
    errorEl.textContent = 'Password errata o vault corrotto.';
  }
}

// ------------------------------------------------------------
// CIFRA E SALVA: serializza le entry in JSON, le cifra,
// e conserva il file cifrato in localStorage.
// Nota: ciò che è in localStorage è GIÀ cifrato.
// ------------------------------------------------------------
async function saveVault(password) {
  const vault = await encryptVault(JSON.stringify(entries), password);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(vault));
}

// ------------------------------------------------------------
// BLOCCA: svuota la memoria. Dopo questo, nessun dato sensibile
// resta accessibile senza ridigitare la password.
// ------------------------------------------------------------
function lock() {
  vaultKey = null;
  entries = [];
  document.getElementById('masterPassword').value = '';
  document.getElementById('vaultScreen').classList.add('hidden');
  document.getElementById('unlockScreen').classList.remove('hidden');
}

function showVaultScreen() {
  document.getElementById('unlockScreen').classList.add('hidden');
  document.getElementById('vaultScreen').classList.remove('hidden');
  renderEntries();
}

// ------------------------------------------------------------
// AGGIUNGI UNA NUOVA ENTRY
// ------------------------------------------------------------
async function addEntry() {
  const site = document.getElementById('siteName').value.trim();
  const user = document.getElementById('siteUser').value.trim();
  const pass = document.getElementById('sitePass').value;
  const errorEl = document.getElementById('addError');
  errorEl.textContent = '';

  if (!site || !user || !pass) {
    errorEl.textContent = 'Compila tutti i campi.';
    return;
  }

  entries.push({ site, user, pass });
  await saveVault(vaultKey);

  // Reset del form
  document.getElementById('siteName').value = '';
  document.getElementById('siteUser').value = '';
  document.getElementById('sitePass').value = '';
  document.getElementById('genStrength').textContent = '';
  renderEntries();
}

// ------------------------------------------------------------
// MOSTRA / NASCONDI PASSWORD DI UNA ENTRY
// ------------------------------------------------------------
function togglePass(btn, entry) {
  const span = btn.previousElementSibling;
  if (span.dataset.hidden === 'true') {
    span.textContent = entry.pass;
    span.dataset.hidden = 'false';
    btn.textContent = '🙈';
  } else {
    span.textContent = '•'.repeat(Math.min(entry.pass.length, 16));
    span.dataset.hidden = 'true';
    btn.textContent = '👁️';
  }
}

async function deleteEntry(index) {
  entries.splice(index, 1);
  await saveVault(vaultKey);
  renderEntries();
}

function renderEntries() {
  const container = document.getElementById('entries');
  container.innerHTML = '';

  if (entries.length === 0) {
    container.innerHTML = '<p class="hint">Nessuna password salvata. Aggiungine una qui sopra!</p>';
    return;
  }

  entries.forEach((entry, index) => {
    const div = document.createElement('div');
    div.className = 'entry';
    div.innerHTML = `
      <div class="info">
        <div class="site">${escapeHtml(entry.site)}</div>
        <div class="user">${escapeHtml(entry.user)}</div>
        <span class="pass" data-hidden="true">${'•'.repeat(Math.min(entry.pass.length, 16))}</span>
      </div>
      <div>
        <button class="btn-small" title="Mostra/nascondi">👁️</button>
        <button class="btn-small" title="Elimina">🗑️</button>
      </div>`;

    const [viewBtn, delBtn] = div.querySelectorAll('button');
    viewBtn.onclick = () => togglePass(viewBtn, entry);
    delBtn.onclick = () => deleteEntry(index);

    container.appendChild(div);
  });
}

// ------------------------------------------------------------
// Piccola protezione contro HTML injection: le entry sono
// inserite dall'utente e non ci fidiamo nemmeno di noi stessi
// ------------------------------------------------------------
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ------------------------------------------------------------
// GENERAZIONE + INDICATORE DI ROBUSTEZZA
// ------------------------------------------------------------
function handleGenerate() {
  const pwd = generatePassword(20);
  document.getElementById('sitePass').value = pwd;
  const entropy = passwordStrength(pwd);
  document.getElementById('genStrength').textContent =
    `Entropia: ${entropy} bit — eccellente 🔒`;
  document.getElementById('genStrength').style.color = '#8ee000';
}

// ------------------------------------------------------------
// BREACH CHECK
// ------------------------------------------------------------
async function handleBreachCheck() {
  const pwd = document.getElementById('checkPass').value;
  const resultEl = document.getElementById('checkResult');
  resultEl.style.color = '';

  if (!pwd) {
    resultEl.textContent = 'Inserisci una password da verificare.';
    return;
  }

  resultEl.textContent = '⏳ Verifica in corso (la password non lascia mai questo browser)...';

  try {
    const count = await checkPasswordBreach(pwd);
    if (count > 0) {
      resultEl.textContent = `🚨 ATTENZIONE: questa password è apparsa in ${count.toLocaleString()} data breach. Cambiala SUBITO.`;
      resultEl.style.color = '#ff8080';
    } else {
      resultEl.textContent = `✅ Mai apparsa nei breach noti. Ottima password!`;
      resultEl.style.color = '#8ee000';
    }
  } catch (e) {
    resultEl.textContent = 'Errore di connessione all’API. Riprova.';
  }

  document.getElementById('checkPass').value = '';
}

// ------------------------------------------------------------
// EXPORT: scarica il file cifrato (NON in chiaro!)
// ------------------------------------------------------------
function exportVault() {
  const data = localStorage.getItem(STORAGE_KEY);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = 'cybervault-backup.json';
  a.click();

  URL.revokeObjectURL(url);
}

// ------------------------------------------------------------
// EVENT LISTENERS
// ------------------------------------------------------------
document.getElementById('unlockBtn').onclick = unlock;
document.getElementById('lockBtn').onclick = lock;
document.getElementById('addBtn').onclick = addEntry;
document.getElementById('generateBtn').onclick = handleGenerate;
document.getElementById('checkBtn').onclick = handleBreachCheck;
document.getElementById('exportBtn').onclick = exportVault;

// Invio con il tasto Invio apre il vault
document.getElementById('masterPassword').addEventListener('keydown', e => {
  if (e.key === 'Enter') unlock();
});

init();
