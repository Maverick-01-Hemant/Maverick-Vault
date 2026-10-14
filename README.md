# Local Password Vault

A local-only Windows password manager. It encrypts one vault file with Argon2id-derived AES-256-GCM encryption. It makes no network requests and has no password-recovery mechanism.

## Run

Use Python 3.11 or newer:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
py vault_crypto.py
py main.py
```

The self-test runs only against a temporary test vault and does not print passwords.

## Vault location

The application stores its vault at `%APPDATA%\PasswordVault\vault.dat` (typically `C:\Users\<you>\AppData\Roaming\PasswordVault\vault.dat`). The file contains a public salt, a fresh nonce, and authenticated ciphertext. Back it up safely: a forgotten master password cannot be recovered.

## Security notes

Keep your device account protected and close/lock the app when away. The vault is decrypted while it is unlocked. Password copying clears the clipboard after 25 seconds only when its contents have not changed.
