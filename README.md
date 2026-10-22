# My Password Vault

A local desktop password manager with authenticated encryption, password generation, encrypted export/import, and recovery-key support.

> **Security notice:** This project is intended for learning and local use. Review the code before storing high-value credentials. Never commit a vault file, recovery key, master password, API key, or `.env` file to GitHub.

## What was fixed in v2

- Removed the insecure 1–4 digit PIN requirement; new vaults require an 8–128 character master password.
- Fixed the unlock bug where a failed decryption could still leave the app marked as unlocked.
- Fixed recovery-key rotation when changing the master password. The old recovery key is invalidated and a new one is shown once.
- Added versioned vault format validation and rejection of corrupt/outdated files.
- Added atomic writes and restrictive `0600` permissions on Unix-like systems.
- Added encrypted export/import validation.
- Added reliable password generation using `secrets`, including character-type guarantees.
- Added regression tests for persistence, wrong-password handling, recovery, rotation, permissions, and import validation.
- Vault contents are encrypted with Fernet (authenticated encryption) and keys are derived with PBKDF2-HMAC-SHA256.

## Install and run

### Linux/macOS

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

The default vault is stored outside the repository at `~/.my_password_vault/password_vault.json`. You can choose another location with the `PASSWORD_VAULT_FILE` environment variable.

## Test

```bash
python -m unittest -v test_vault.py
python -m py_compile main.py
```

## Recovery and backups

The recovery key is displayed once when a vault is created and again after the master password is changed. Store it offline. Anyone who has it can unlock the vault. Exported `.vault` files remain encrypted, but should still be kept private.

This v2 format intentionally does not silently migrate the old insecure 1–4 digit vault format. Export or remove any old vault only after verifying its contents, then create a new v2 vault.
