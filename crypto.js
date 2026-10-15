// ============================================================
//  CYBERVAULT — MODULO CRITTOGRAFICO
//  Qui vivono tutte le operazioni di cifratura.
//  Usiamo la Web Crypto API (crypto.subtle), integrata nei
//  browser moderni: nessuna libreria esterna necessaria.
// ============================================================

const PBKDF2_ITERATIONS = 310000; // raccomandato da OWASP per PBKDF2-SHA256

// ------------------------------------------------------------
// CONVERSIONE BASE64 <-> ArrayBuffer
// I dati binari (sale, IV, testo cifrato) vanno salvati come
// testo nel file JSON: base64 è l'alfabeto che li rappresenta.
// ------------------------------------------------------------
function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// ------------------------------------------------------------
// DERIVAZIONE DELLA CHIAVE (PBKDF2)
// Una password umana non può essere usata direttamente come
// chiave AES: è corta, prevedibile, non è binaria.
// PBKDF2 "stira" la password tramite hashing ripetuto
// (310.000 iterazioni) + un SALT casuale, producendo una
// chiave AES-256 a 256 bit indistinguibile da casuale.
//
// Il SALT serve perché due utenti con la stessa password
// NON devono ottenere la stessa chiave (altrimenti il
// database dei vault rivelerebbe password uguali).
// ------------------------------------------------------------
async function deriveKey(masterPassword, salt) {
  const enc = new TextEncoder();

  // Passo 1: importiamo la password come materiale grezzo
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(masterPassword),
    'PBKDF2',
    false,          // la chiave "grezza" non esce da qui
    ['deriveKey']
  );

  // Passo 2: la stiratura vera e propria
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,                     // casuale, salvato in chiaro nel file
      iterations: PBKDF2_ITERATIONS,  // rende brute-force lentissimo
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 }, // obiettivo: chiave AES-256
    false,                            // extractable=false: la chiave non lascia mai il browser
    ['encrypt', 'decrypt']
  );
}

// ------------------------------------------------------------
// CIFRATURA DEL VAULT (AES-256-GCM)
// AES-GCM è crittografia simmetrica autenticata:
//  - CONFIDENZIALITÀ: senza la chiave il contenuto è indistinguibile da rumore
//  - INTEGRITÀ: se qualcuno altera anche UN SOLO BYTE del file cifrato,
//    la decifratura fallisce (rileviamo manomissioni!)
//
// L'IV (vettore di inizializzazione) è casuale e serve perché
// cifrare lo stesso testo due volte deve dare risultati diversi,
// altrimenti un osservatore capirebbe quando i contenuti coincidono.
// ------------------------------------------------------------
async function encryptVault(plainText, masterPassword) {
  const salt = crypto.getRandomValues(new Uint8Array(16)); // 128 bit di sale
  const iv   = crypto.getRandomValues(new Uint8Array(12)); // 96 bit: la dimensione standard per GCM

  const key = await deriveKey(masterPassword, salt);

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    new TextEncoder().encode(plainText)
  );

  // Il file del vault contiene TUTTO ciò che serve a decifrare,
  // tranne ovviamente la master password
  return {
    salt: bufToBase64(salt),
    iv: bufToBase64(iv),
    data: bufToBase64(cipherBuffer)
  };
}

// ------------------------------------------------------------
// DECIFRATURA: ricostruisce la chiave (stesso sale!) e
// verifica integrità. Se la password è sbagliata o il file
// è stato manomesso, GCM ci avvisa con un'eccezione.
// ------------------------------------------------------------
async function decryptVault(vault, masterPassword) {
  const salt = base64ToBuf(vault.salt);
  const iv   = base64ToBuf(vault.iv);
  const key  = await deriveKey(masterPassword, salt);

  const plainBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    base64ToBuf(vault.data)
  );

  return new TextDecoder().decode(plainBuffer);
}

// ------------------------------------------------------------
// GENERATORE DI PASSWORD CRIPTOGRAFICAMENTE SICURO
// Math.random() NON va bene: è un PRNG prevedibile!
// crypto.getRandomValues() usa il generatore di entropia del
// sistema operativo (rumore hardware: tempi di tasti, ecc.).
// ------------------------------------------------------------
function generatePassword(length = 20) {
  const charset =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?';
  const randomValues = crypto.getRandomValues(new Uint32Array(length));
  let password = '';
  for (let i = 0; i < length; i++) {
    // modulo per mappare il numero casuale dentro il charset
    password += charset[randomValues[i] % charset.length];
  }
  return password;
}

// ------------------------------------------------------------
// STIMA DELLA ROBUSTEZZA (entropia in bit)
// Entropia = lunghezza × log2(dimensione dell'alfabeto usato).
// Più bit = più combinazioni = brute-force più lungo.
//  - < 45 bit   → debole
//  - 45-80 bit  → discreta
//  - > 80 bit   → eccellente
// ------------------------------------------------------------
function passwordStrength(password) {
  let alphabetSize = 0;
  if (/[a-z]/.test(password))    alphabetSize += 26;
  if (/[A-Z]/.test(password))    alphabetSize += 26;
  if (/[0-9]/.test(password))    alphabetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) alphabetSize += 33;

  if (alphabetSize === 0 || password.length === 0) return 0;

  const entropy = Math.round(password.length * Math.log2(alphabetSize));
  return entropy;
}

// ------------------------------------------------------------
// VERIFICA DATA BREACH (k-anonymity di HaveIBeenPwned)
// Genio della crittografia applicata: NON inviamo mai la
// password all'API. La hashiamo in SHA-1, mandiamo SOLO i
// primi 5 caratteri dell'hash, e il server risponde con
// TUTTI gli hash che iniziano così. Controlliamo in locale
// se il nostro hash completo è nella lista, insieme al
// numero di volte che è trapelato. Il server non saprà MAI
// quale password cercavamo.
// ------------------------------------------------------------
async function checkPasswordBreach(password) {
  // SHA-1 via Web Crypto
  const digest = await crypto.subtle.digest(
    'SHA-1',
    new TextEncoder().encode(password)
  );
  const sha1 = Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();

  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  // Chiamata all'API pubblica e gratuita di HaveIBeenPwned
  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  if (!response.ok) throw new Error('API non raggiungibile');

  const body = await response.text();
  const lines = body.split('\n');

  // Il server ha mandato solo i SUFFIX: cerchiamo il nostro in locale
  for (const line of lines) {
    const [hashSuffix, count] = line.trim().split(':');
    if (hashSuffix === suffix) {
      return parseInt(count, 10); // password trovata in N breach!
    }
  }
  return 0; // non trovata: mai trapelata (per quanto ne sappiamo)
}
