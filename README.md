# 🔐 CyberVault

Un gestore di password cifrato con AES-256-GCM, interamente nel browser.
Nessuna libreria esterna, nessun server: le tue password non lasciano mai il PC.

## Concetti imparati

- **PBKDF2**: come si deriva una chiave crittografica da una password umana
- **Sale (salt)** e **IV**: perché servono e perché sono salvati in chiaro
- **AES-256-GCM**: cifratura simmetrica con autenticazione (rilevamento manomissioni)
- **Web Crypto API**: `crypto.subtle` e `crypto.getRandomValues`
- **k-anonymity**: come verificare una password nei data breach senza inviarla
- **Entropia delle password**: come stimare la resistenza al brute-force

## Come usarlo

Apri `index.html`, scegli una master password (prima volta) o inseriscila (vault esistente).

⚠️ Se dimentichi la master password, il vault è perso PER SEMPRE.
   Nessuno può recuperarlo. Proprio come deve funzionare.
