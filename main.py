from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import string
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk
import pyperclip
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


APP_NAME = "My Password Vault"
VAULT_VERSION = 2
KDF_ITERATIONS = 600_000
MIN_MASTER_PASSWORD_LENGTH = 8
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?"


class VaultError(Exception):
    """Expected vault/data error shown to the user."""


class PasswordVault:
    """Encrypted local password vault.

    The vault stores only salted verifiers and Fernet-encrypted data. The master
    password and recovery key are never written to disk. Writes are atomic and
    the file is restricted to the current user where supported.
    """

    def __init__(self, vault_file: str | os.PathLike | None = None):
        default_path = Path.home() / ".my_password_vault" / "password_vault.json"
        self.vault_file = Path(vault_file or os.environ.get("PASSWORD_VAULT_FILE", default_path))
        self.salt: bytes | None = None
        self.master_verifier: str | None = None
        self.recovery_verifier: str | None = None
        self.recovery_encrypted_key: str | None = None
        self.encrypted_blob: str | None = None
        self.key: bytes | None = None
        self.passwords: list[dict] = []
        self.load_vault()

    @staticmethod
    def validate_master_password(password: str) -> bool:
        return MIN_MASTER_PASSWORD_LENGTH <= len(password) <= 128 and not password.isspace()

    @staticmethod
    def normalize_recovery_key(value: str) -> str:
        return value.strip().upper().replace(" ", "")

    def _derive_key(self, secret: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(secret.encode("utf-8")))

    @staticmethod
    def _verifier(key: bytes) -> str:
        return hashlib.sha256(key).hexdigest()

    def _require_unlocked(self) -> None:
        if self.key is None:
            raise VaultError("Vault is locked")

    def generate_recovery_key(self) -> str:
        alphabet = string.ascii_uppercase + string.digits
        return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(6))

    def set_master_password(self, password: str) -> tuple[bool, str]:
        if not self.validate_master_password(password):
            return False, ""
        self.salt = secrets.token_bytes(16)
        self.key = self._derive_key(password, self.salt)
        self.master_verifier = self._verifier(self.key)
        recovery_key = self.generate_recovery_key()
        recovery_derived = self._derive_key(recovery_key, self.salt)
        self.recovery_verifier = self._verifier(recovery_derived)
        self.recovery_encrypted_key = Fernet(recovery_derived).encrypt(self.key).decode("ascii")
        self.passwords = []
        self.encrypted_blob = None
        self.save_vault()
        return True, recovery_key

    def _decrypt_passwords(self, key: bytes) -> list[dict]:
        if not self.encrypted_blob:
            return []
        try:
            plain = Fernet(key).decrypt(self.encrypted_blob.encode("ascii"))
            entries = json.loads(plain.decode("utf-8"))
            if not isinstance(entries, list):
                raise VaultError("Vault data has an invalid format")
            return entries
        except (InvalidToken, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise VaultError("Vault password is incorrect or vault data is corrupt") from exc

    def unlock_master(self, password: str) -> bool:
        if not self.salt or not self.master_verifier:
            return False
        candidate = self._derive_key(password, self.salt)
        if not secrets.compare_digest(self._verifier(candidate), self.master_verifier):
            return False
        try:
            entries = self._decrypt_passwords(candidate)
        except VaultError:
            self.lock()
            return False
        self.key, self.passwords = candidate, entries
        return True

    def unlock_recovery(self, recovery_key: str) -> bool:
        if not self.salt or not self.recovery_verifier or not self.recovery_encrypted_key:
            return False
        normalized = self.normalize_recovery_key(recovery_key)
        candidate = self._derive_key(normalized, self.salt)
        if not secrets.compare_digest(self._verifier(candidate), self.recovery_verifier):
            return False
        try:
            master_key = Fernet(candidate).decrypt(self.recovery_encrypted_key.encode("ascii"))
            entries = self._decrypt_passwords(master_key)
        except (InvalidToken, VaultError, ValueError):
            self.lock()
            return False
        self.key, self.passwords = master_key, entries
        return True

    def change_master_password(self, new_password: str) -> tuple[bool, str]:
        self._require_unlocked()
        if not self.validate_master_password(new_password):
            return False, ""
        new_key = self._derive_key(new_password, self.salt)
        new_recovery = self.generate_recovery_key()
        recovery_key = self._derive_key(new_recovery, self.salt)
        self.key = new_key
        self.master_verifier = self._verifier(new_key)
        self.recovery_verifier = self._verifier(recovery_key)
        self.recovery_encrypted_key = Fernet(recovery_key).encrypt(new_key).decode("ascii")
        self.save_vault()
        return True, new_recovery

    def save_vault(self) -> None:
        if not self.salt or not self.key:
            raise VaultError("Vault is not initialized")
        payload = {
            "version": VAULT_VERSION,
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "master_verifier": self.master_verifier,
            "recovery_verifier": self.recovery_verifier,
            "recovery_encrypted_key": self.recovery_encrypted_key,
            "encrypted_data": Fernet(self.key).encrypt(
                json.dumps(self.passwords, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("ascii"),
        }
        self.vault_file.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".vault-", dir=str(self.vault_file.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.vault_file)
            try:
                os.chmod(self.vault_file, 0o600)
            except OSError:
                pass
        except Exception as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise VaultError(f"Vault save failed: {exc}") from exc

    def load_vault(self) -> None:
        if not self.vault_file.exists():
            return
        try:
            with self.vault_file.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if data.get("version") != VAULT_VERSION:
                raise VaultError("This vault format is outdated. Create a new vault or restore a v2 backup.")
            self.salt = base64.b64decode(data["salt"], validate=True)
            self.master_verifier = data["master_verifier"]
            self.recovery_verifier = data["recovery_verifier"]
            self.recovery_encrypted_key = data["recovery_encrypted_key"]
            self.encrypted_blob = data["encrypted_data"]
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise VaultError("Vault file is missing, unreadable, or corrupt") from exc

    def lock(self) -> None:
        self.key = None
        self.passwords = []

    def add_password(self, platform: str, username: str, password: str, notes: str = "",
                     category: str = "General", tags: str = "", expiry_days: int = 0) -> bool:
        self._require_unlocked()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.passwords.append({
            "id": secrets.token_hex(16), "platform": platform.strip(),
            "username": username.strip(), "password": password,
            "notes": notes.strip(), "category": category, "tags": tags.strip(),
            "created": now, "updated": now,
            "expiry": (datetime.now() + timedelta(days=expiry_days)).strftime("%Y-%m-%d") if expiry_days > 0 else "",
        })
        self.save_vault()
        return True

    def get_all(self) -> list[dict]:
        self._require_unlocked()
        return [entry.copy() for entry in self.passwords]

    def delete_password(self, entry_id: str) -> bool:
        self._require_unlocked()
        before = len(self.passwords)
        self.passwords = [entry for entry in self.passwords if entry.get("id") != entry_id]
        if len(self.passwords) == before:
            return False
        self.save_vault()
        return True

    def export_to(self, destination: str | os.PathLike) -> None:
        if not self.vault_file.exists():
            raise VaultError("No vault exists to export")
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.vault_file, destination)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass

    def import_from(self, source: str | os.PathLike) -> None:
        source = Path(source)
        try:
            candidate = PasswordVault(source)
        except VaultError:
            raise VaultError("Import rejected: file is not a valid v2 vault")
        if not candidate.salt or not candidate.master_verifier:
            raise VaultError("Import rejected: incomplete vault")
        self.vault_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.vault_file.with_suffix(self.vault_file.suffix + ".import")
        shutil.copy2(source, temporary)
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self.vault_file)
        self.__init__(self.vault_file)


class PasswordGeneratorApp:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.window = ctk.CTk()
        self.window.title(APP_NAME)
        self.window.geometry("920x780")
        self.window.minsize(800, 650)
        self.vault = PasswordVault()
        self.vault_unlocked = False
        self.current_tab = "🔑 Generator"
        self.current_theme = "dark"
        self.password_visible = False
        self.clipboard_job = None
        self.recent_platforms: list[str] = []
        self.create_widgets()
        if not self.vault.master_verifier:
            self.show_setup_vault()
        else:
            self.update_saved_display()

    def register_activity(self, _event=None):
        return None

    def create_widgets(self):
        self.window.bind("<Any-KeyPress>", self.register_activity)
        self.window.bind("<Any-Button>", self.register_activity)
        top = ctk.CTkFrame(self.window, height=50, corner_radius=0)
        top.pack(fill="x")
        top.pack_propagate(False)
        ctk.CTkLabel(top, text="🔐 My Password Vault", font=ctk.CTkFont(size=18, weight="bold")).pack(side="left", padx=20)
        self.theme_btn = ctk.CTkButton(top, text="🌙 Dark", width=90, command=self.toggle_theme)
        self.theme_btn.pack(side="right", padx=10)
        self.vault_status_label = ctk.CTkLabel(top, text="🔒 Locked", font=ctk.CTkFont(size=13, weight="bold"), text_color="#ff4444")
        self.vault_status_label.pack(side="right", padx=10)
        self.tabview = ctk.CTkTabview(self.window, width=880, height=680, command=self.on_tab_change)
        self.tabview.pack(pady=10, padx=15, fill="both", expand=True)
        for name in ("🔑 Generator", "💾 Vault", "⚙️ Settings"):
            self.tabview.add(name)
        self.build_generator_tab()
        self.build_vault_tab()
        self.build_settings_tab()
        status_frame = ctk.CTkFrame(self.window, height=32, corner_radius=0)
        status_frame.pack(fill="x", side="bottom")
        self.status_label = ctk.CTkLabel(status_frame, text="Ready")
        self.status_label.pack(side="left", padx=15)

    @staticmethod
    def password_ok(value: str) -> bool:
        return bool(value and value != "Click Generate")

    def show_setup_vault(self):
        win = ctk.CTkToplevel(self.window)
        win.title("Create Vault")
        win.geometry("460x330")
        win.resizable(False, False)
        win.transient(self.window)
        win.grab_set()
        ctk.CTkLabel(win, text="🔐 Create Master Password", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=18)
        ctk.CTkLabel(win, text=f"Use at least {MIN_MASTER_PASSWORD_LENGTH} characters (not a short PIN)").pack()
        first = ctk.CTkEntry(win, placeholder_text="Master password", show="*", width=340, height=40)
        first.pack(pady=10)
        second = ctk.CTkEntry(win, placeholder_text="Confirm master password", show="*", width=340, height=40)
        second.pack(pady=5)
        def create():
            if not self.vault.validate_master_password(first.get()):
                messagebox.showerror("Error", f"Password must be {MIN_MASTER_PASSWORD_LENGTH}-128 characters and not only spaces")
                return
            if first.get() != second.get():
                messagebox.showerror("Error", "Passwords do not match")
                return
            try:
                _, recovery = self.vault.set_master_password(first.get())
                win.destroy()
                self.show_recovery_key_screen(recovery, "Vault created. Save this new recovery key securely.")
            except VaultError as exc:
                messagebox.showerror("Error", str(exc))
        ctk.CTkButton(win, text="Create Vault", command=create, height=42).pack(pady=15)
        ctk.CTkLabel(win, text="Never store the recovery key in GitHub, chat, or screenshots", text_color="#ffaa00").pack()
        first.focus()

    def show_recovery_key_screen(self, recovery_key: str, message: str):
        win = ctk.CTkToplevel(self.window)
        win.title("Recovery Key")
        win.geometry("580x420")
        win.resizable(False, False)
        win.transient(self.window)
        win.grab_set()
        ctk.CTkLabel(win, text="⚠️ RECOVERY KEY", font=ctk.CTkFont(size=22, weight="bold"), text_color="#ff4444").pack(pady=(20, 8))
        ctk.CTkLabel(win, text=message + "\nThis key is shown only once.", justify="center").pack(pady=5)
        key_label = ctk.CTkLabel(win, text=recovery_key, font=ctk.CTkFont(size=18, weight="bold", family="Consolas"), text_color="#00ff88")
        key_label.pack(pady=18)
        def copy_key():
            pyperclip.copy(recovery_key)
            messagebox.showinfo("Copied", "Recovery key copied. Clear your clipboard after storing it securely.")
        ctk.CTkButton(win, text="📋 Copy Recovery Key", command=copy_key, width=220).pack(pady=5)
        ctk.CTkLabel(win, text="Write it down and keep it offline. Anyone with this key can unlock the vault.", text_color="#ffaa00", wraplength=480).pack(pady=15)
        ctk.CTkButton(win, text="I saved the key", command=win.destroy, width=220).pack(pady=5)

    def show_recovery_flow(self):
        win = ctk.CTkToplevel(self.window)
        win.title("Recover Vault")
        win.geometry("460x390")
        win.resizable(False, False)
        win.transient(self.window)
        win.grab_set()
        ctk.CTkLabel(win, text="🔑 Recover with Recovery Key", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        recovery = ctk.CTkEntry(win, placeholder_text="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX", width=350)
        recovery.pack(pady=8)
        new_pw = ctk.CTkEntry(win, placeholder_text="New master password (8+ chars)", show="*", width=350)
        new_pw.pack(pady=8)
        confirm = ctk.CTkEntry(win, placeholder_text="Confirm new password", show="*", width=350)
        confirm.pack(pady=8)
        def recover():
            if new_pw.get() != confirm.get() or not self.vault.validate_master_password(new_pw.get()):
                messagebox.showerror("Error", f"New password must be {MIN_MASTER_PASSWORD_LENGTH}+ characters and match")
                return
            if not self.vault.unlock_recovery(recovery.get()):
                messagebox.showerror("Error", "Invalid recovery key or corrupt vault")
                return
            try:
                ok, new_recovery = self.vault.change_master_password(new_pw.get())
                if ok:
                    self.vault_unlocked = True
                    self.vault_status_label.configure(text="🔓 Unlocked", text_color="#44ff44")
                    win.destroy()
                    self.update_saved_display()
                    self.show_recovery_key_screen(new_recovery, "Password changed. Your old recovery key is no longer valid.")
            except VaultError as exc:
                messagebox.showerror("Error", str(exc))
        ctk.CTkButton(win, text="Recover Vault", command=recover, height=42).pack(pady=15)

    def show_unlock_dialog(self, callback=None):
        if self.vault_unlocked:
            if callback: callback()
            return
        win = ctk.CTkToplevel(self.window)
        win.title("Unlock Vault")
        win.geometry("420x270")
        win.resizable(False, False)
        win.transient(self.window)
        win.grab_set()
        ctk.CTkLabel(win, text="🔐 Enter Master Password", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        entry = ctk.CTkEntry(win, placeholder_text="Master password", show="*", width=320, height=40)
        entry.pack(pady=8)
        error = ctk.CTkLabel(win, text="", text_color="#ff4444")
        error.pack()
        def check():
            if self.vault.unlock_master(entry.get()):
                self.vault_unlocked = True
                self.vault_status_label.configure(text="🔓 Unlocked", text_color="#44ff44")
                win.destroy()
                self.update_saved_display()
                self.status_label.configure(text="Vault unlocked", text_color="#44ff44")
                if callback: callback()
            else:
                error.configure(text="Incorrect password or corrupt vault")
                entry.delete(0, "end")
                entry.focus()
        ctk.CTkButton(win, text="Unlock", command=check, height=40, width=150).pack(pady=10)
        ctk.CTkButton(win, text="Forgot password? Use recovery key", fg_color="transparent", text_color="#88aaff", command=lambda: [win.destroy(), self.show_recovery_flow()]).pack()
        entry.bind("<Return>", lambda _event: check())
        entry.focus()

    def lock_vault(self):
        self.vault.lock()
        self.vault_unlocked = False
        self.vault_status_label.configure(text="🔒 Locked", text_color="#ff4444")
        self.update_saved_display()

    def on_tab_change(self):
        current = self.tabview.get()
        if self.current_tab == "💾 Vault" and current != "💾 Vault" and self.vault_unlocked:
            self.lock_vault()
            self.status_label.configure(text="Vault locked after leaving Vault tab", text_color="#ffaa00")
        if current == "💾 Vault" and not self.vault_unlocked:
            self.show_unlock_dialog()
        self.current_tab = current

    def toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        ctk.set_appearance_mode(self.current_theme)
        self.theme_btn.configure(text="☀️ Light" if self.current_theme == "light" else "🌙 Dark")

    def build_generator_tab(self):
        tab = self.tabview.tab("🔑 Generator")
        display = ctk.CTkFrame(tab)
        display.pack(fill="x", padx=15, pady=12)
        self.password_var = ctk.StringVar(value="Click Generate")
        self.password_entry = ctk.CTkEntry(display, textvariable=self.password_var, font=ctk.CTkFont(size=18), height=48, state="readonly")
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(10, 5), pady=10)
        actions = ctk.CTkFrame(display, fg_color="transparent")
        actions.pack(side="right", padx=10)
        self.copy_btn = ctk.CTkButton(actions, text="📋 Copy", width=80, command=self.copy_password)
        self.copy_btn.pack(side="left", padx=3)
        ctk.CTkButton(actions, text="👁️", width=40, command=self.toggle_visibility).pack(side="left", padx=3)
        self.strength_label = ctk.CTkLabel(tab, text="Strength: —", font=ctk.CTkFont(size=14, weight="bold"))
        self.strength_label.pack()
        self.strength_bar = ctk.CTkProgressBar(tab, width=450)
        self.strength_bar.pack(pady=4)
        self.strength_bar.set(0)
        self.strength_feedback = ctk.CTkLabel(tab, text="")
        self.strength_feedback.pack()
        options = ctk.CTkFrame(tab)
        options.pack(fill="x", padx=15, pady=10)
        left = ctk.CTkFrame(options, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=10)
        ctk.CTkLabel(left, text="Generator settings", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w")
        row = ctk.CTkFrame(left, fg_color="transparent")
        row.pack(fill="x", pady=6)
        ctk.CTkLabel(row, text="Length").pack(side="left")
        self.length_var = ctk.IntVar(value=16)
        self.len_label = ctk.CTkLabel(row, text="16", width=30)
        ctk.CTkSlider(row, from_=8, to=64, variable=self.length_var, command=lambda value: self.len_label.configure(text=str(int(float(value))))).pack(side="left", fill="x", expand=True, padx=8)
        self.len_label.pack(side="right")
        self.upper_v, self.lower_v, self.digit_v, self.special_v = (ctk.BooleanVar(value=True) for _ in range(4))
        self.exclude_v = ctk.BooleanVar(value=True)
        self.passphrase_v = ctk.BooleanVar(value=False)
        for label, variable in (("Uppercase", self.upper_v), ("Lowercase", self.lower_v), ("Digits", self.digit_v), ("Special", self.special_v), ("Exclude similar (il1Lo0O)", self.exclude_v), ("Generate passphrase", self.passphrase_v)):
            ctk.CTkCheckBox(left, text=label, variable=variable).pack(anchor="w", pady=1)
        right = ctk.CTkFrame(options, fg_color="transparent")
        right.pack(side="right", fill="both", expand=True, padx=10)
        ctk.CTkLabel(right, text="Save info", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w")
        self.platform_var = ctk.StringVar(value="General")
        platforms = ["General", "Facebook", "Instagram", "WhatsApp", "Telegram", "TikTok", "YouTube", "Twitter/X", "Gmail", "Outlook", "Banking", "Netflix", "Spotify", "Discord", "GitHub", "Work", "Personal"]
        ctk.CTkOptionMenu(right, values=platforms, variable=self.platform_var, width=220).pack(anchor="w", pady=5)
        self.username_var = ctk.StringVar()
        ctk.CTkEntry(right, textvariable=self.username_var, placeholder_text="Username / email", width=240).pack(anchor="w", pady=5)
        self.notes_var = ctk.StringVar()
        ctk.CTkEntry(right, textvariable=self.notes_var, placeholder_text="Notes (optional)", width=240).pack(anchor="w", pady=5)
        self.category_var = ctk.StringVar(value="General")
        ctk.CTkOptionMenu(right, values=["General", "Social", "Banking", "Work", "Personal", "Entertainment", "Shopping"], variable=self.category_var, width=220).pack(anchor="w", pady=5)
        buttons = ctk.CTkFrame(tab, fg_color="transparent")
        buttons.pack(pady=12)
        ctk.CTkButton(buttons, text="🔑 Generate Password", width=180, height=42, command=self.generate_password).pack(side="left", padx=6)
        ctk.CTkButton(buttons, text="💾 Save to Vault", width=160, height=42, fg_color="#2b6e4e", command=self.save_to_vault).pack(side="left", padx=6)

    def build_vault_tab(self):
        tab = self.tabview.tab("💾 Vault")
        controls = ctk.CTkFrame(tab)
        controls.pack(fill="x", padx=15, pady=8)
        ctk.CTkButton(controls, text="📤 Export", width=90, command=self.export_vault).pack(side="left", padx=4)
        ctk.CTkButton(controls, text="📥 Import", width=90, command=self.import_vault).pack(side="left", padx=4)
        search_frame = ctk.CTkFrame(tab)
        search_frame.pack(fill="x", padx=15, pady=4)
        ctk.CTkLabel(search_frame, text="🔍").pack(side="left", padx=5)
        self.search_var = ctk.StringVar()
        search = ctk.CTkEntry(search_frame, textvariable=self.search_var, placeholder_text="Search platform, username, notes, category...")
        search.pack(side="left", fill="x", expand=True, padx=5)
        search.bind("<KeyRelease>", lambda _event: self.update_saved_display())
        self.saved_frame = ctk.CTkScrollableFrame(tab, height=500)
        self.saved_frame.pack(fill="both", expand=True, padx=15, pady=8)

    def build_settings_tab(self):
        tab = self.tabview.tab("⚙️ Settings")
        ctk.CTkLabel(tab, text="Settings", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        ctk.CTkLabel(tab, text=f"Master password: {MIN_MASTER_PASSWORD_LENGTH}+ characters").pack(pady=5)
        ctk.CTkLabel(tab, text="Encryption: Fernet authenticated encryption + PBKDF2-HMAC-SHA256").pack(pady=5)
        ctk.CTkLabel(tab, text=f"KDF work factor: {KDF_ITERATIONS:,} iterations").pack(pady=5)
        ctk.CTkLabel(tab, text="Vault locks automatically when you leave the Vault tab").pack(pady=5)
        ctk.CTkButton(tab, text="Change Master Password", command=self.change_master_password).pack(pady=20)

    def generate_password(self):
        if self.passphrase_v.get():
            words = "apple bridge cloud dragon eagle forest galaxy harbor island jungle knight lemon mountain nebula ocean panda quartz river sunset tiger umbrella valley whisper xenon yellow zebra anchor blossom crystal diamond".split()
            count = max(4, min(8, int(self.length_var.get()) // 4))
            password = "-".join(secrets.choice(words) for _ in range(count))
            if self.digit_v.get(): password += str(secrets.randbelow(90) + 10)
        else:
            pools = []
            if self.upper_v.get(): pools.append(string.ascii_uppercase)
            if self.lower_v.get(): pools.append(string.ascii_lowercase)
            if self.digit_v.get(): pools.append(string.digits)
            if self.special_v.get(): pools.append(SPECIAL_CHARS)
            if self.exclude_v.get(): pools = ["".join(c for c in pool if c not in "il1Lo0O") for pool in pools]
            if not pools:
                messagebox.showwarning("Warning", "Select at least one character type")
                return
            all_chars = "".join(pools)
            password_chars = [secrets.choice(pool) for pool in pools]
            password_chars += [secrets.choice(all_chars) for _ in range(max(0, int(self.length_var.get()) - len(password_chars)))]
            secrets.SystemRandom().shuffle(password_chars)
            password = "".join(password_chars)
        self.password_var.set(password)
        self.password_entry.configure(show="*")
        self.password_visible = False
        self.check_strength(password)
        self.status_label.configure(text=f"Generated ({len(password)} characters)", text_color="#44ff44")

    def check_strength(self, password: str):
        score = min(1.0, (min(len(password), 24) / 24) * 0.5 + sum(bool(test) for test in (any(c.isupper() for c in password), any(c.islower() for c in password), any(c.isdigit() for c in password), any(c in SPECIAL_CHARS for c in password))) * 0.125)
        self.strength_bar.set(score)
        if score < .35: label, color, feedback = "🔴 Weak", "#ff4444", "Use a longer password"
        elif score < .6: label, color, feedback = "🟡 Fair", "Add length and character variety"
        elif score < .8: label, color, feedback = "🟢 Strong", "Good password"
        else: label, color, feedback = "💪 Excellent", "Excellent security"
        self.strength_label.configure(text=label, text_color=color)
        self.strength_feedback.configure(text=feedback)

    def toggle_visibility(self):
        if not self.password_ok(self.password_var.get()): return
        self.password_visible = not self.password_visible
        self.password_entry.configure(show="" if self.password_visible else "*")
        if self.password_visible:
            self.window.after(10_000, self.hide_password)

    def hide_password(self):
        self.password_visible = False
        self.password_entry.configure(show="*")

    def copy_password(self):
        if not self.password_ok(self.password_var.get()): return
        pyperclip.copy(self.password_var.get())
        self.status_label.configure(text="Copied; clipboard clears in 30 seconds", text_color="#44ff44")
        if self.clipboard_job: self.window.after_cancel(self.clipboard_job)
        self.clipboard_job = self.window.after(30_000, lambda: pyperclip.copy(""))

    def save_to_vault(self):
        if not self.password_ok(self.password_var.get()):
            messagebox.showinfo("Info", "Generate a password first")
            return
        def do_save():
            try:
                self.vault.add_password(self.platform_var.get(), self.username_var.get() or "user", self.password_var.get(), self.notes_var.get(), self.category_var.get())
                self.update_saved_display()
                self.status_label.configure(text="Saved to encrypted vault", text_color="#44ff44")
            except VaultError as exc: messagebox.showerror("Save error", str(exc))
        if self.vault_unlocked: do_save()
        else: self.show_unlock_dialog(do_save)

    def update_saved_display(self):
        for widget in self.saved_frame.winfo_children(): widget.destroy()
        if not self.vault_unlocked:
            ctk.CTkLabel(self.saved_frame, text="🔒 Vault is locked\nOpen the Vault tab and unlock it", font=ctk.CTkFont(size=15), text_color="#888888").pack(pady=60)
            return
        try: entries = self.vault.get_all()
        except VaultError: return
        query = self.search_var.get().lower()
        entries = [entry for entry in entries if not query or any(query in str(entry.get(key, "")).lower() for key in ("platform", "username", "notes", "tags", "category"))]
        if not entries:
            ctk.CTkLabel(self.saved_frame, text="No passwords found", text_color="#888888").pack(pady=40)
            return
        for entry in sorted(entries, key=lambda item: item.get("updated", ""), reverse=True):
            card = ctk.CTkFrame(self.saved_frame)
            card.pack(fill="x", pady=5, padx=5)
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=10, pady=4)
            ctk.CTkLabel(top, text=entry.get("platform", ""), font=ctk.CTkFont(size=15, weight="bold")).pack(side="left")
            ctk.CTkLabel(top, text=f" • {entry.get('category', '')}", text_color="#88aaff").pack(side="left")
            ctk.CTkLabel(top, text=entry.get("username", ""), text_color="#aaaaaa").pack(side="right")
            mid = ctk.CTkFrame(card, fg_color="transparent")
            mid.pack(fill="x", padx=10, pady=2)
            masked = "•" * min(18, len(entry.get("password", "")))
            password_label = ctk.CTkLabel(mid, text=masked)
            password_label.pack(side="left")
            state = {"visible": False}
            def toggle(label=password_label, value=entry.get("password", ""), mask=masked, state=state):
                state["visible"] = not state["visible"]
                label.configure(text=value if state["visible"] else mask)
                if state["visible"]: self.window.after(10_000, lambda: (label.configure(text=mask), state.update(visible=False)))
            ctk.CTkButton(mid, text="👁️", width=36, height=26, command=toggle).pack(side="left", padx=4)
            def copy(value=entry.get("password", "")):
                pyperclip.copy(value)
                self.status_label.configure(text="Password copied; clipboard clears in 30 seconds", text_color="#44ff44")
                self.window.after(30_000, lambda: pyperclip.copy(""))
            ctk.CTkButton(mid, text="📋 Pass", width=70, height=26, command=copy).pack(side="left", padx=2)
            ctk.CTkButton(mid, text="🗑️", width=36, height=26, fg_color="#8b2f2f", command=lambda item_id=entry.get("id"): self.delete_entry(item_id)).pack(side="right", padx=4)
            if entry.get("notes"): ctk.CTkLabel(card, text=entry["notes"], text_color="#888888").pack(anchor="w", padx=12)

    def delete_entry(self, entry_id):
        if not self.vault_unlocked: return
        if messagebox.askyesno("Confirm", "Delete this password permanently?"):
            try:
                self.vault.delete_password(entry_id)
                self.update_saved_display()
            except VaultError as exc: messagebox.showerror("Delete error", str(exc))

    def export_vault(self):
        if not self.vault_unlocked: messagebox.showinfo("Info", "Unlock the vault first"); return
        path = filedialog.asksaveasfilename(defaultextension=".vault", filetypes=[("Encrypted vault", "*.vault")])
        if path:
            try: self.vault.export_to(path); messagebox.showinfo("Export", "Encrypted vault exported successfully")
            except VaultError as exc: messagebox.showerror("Export error", str(exc))

    def import_vault(self):
        path = filedialog.askopenfilename(filetypes=[("Encrypted vault", "*.vault"), ("JSON", "*.json")])
        if path and messagebox.askyesno("Import", "Replace the current vault? Make sure you have a backup first."):
            try:
                self.vault.import_from(path)
                self.vault_unlocked = False
                self.vault_status_label.configure(text="🔒 Locked", text_color="#ff4444")
                self.update_saved_display()
                messagebox.showinfo("Import", "Vault imported. Unlock it with its master password.")
            except VaultError as exc: messagebox.showerror("Import error", str(exc))

    def change_master_password(self):
        if not self.vault_unlocked:
            self.show_unlock_dialog(self.change_master_password)
            return
        win = ctk.CTkToplevel(self.window)
        win.title("Change Master Password")
        win.geometry("430x270")
        win.transient(self.window); win.grab_set()
        ctk.CTkLabel(win, text="Set a new master password", font=ctk.CTkFont(size=17, weight="bold")).pack(pady=18)
        first = ctk.CTkEntry(win, placeholder_text="New password (8+ chars)", show="*", width=320); first.pack(pady=7)
        second = ctk.CTkEntry(win, placeholder_text="Confirm new password", show="*", width=320); second.pack(pady=7)
        def change():
            if first.get() != second.get() or not self.vault.validate_master_password(first.get()):
                messagebox.showerror("Error", f"Password must be {MIN_MASTER_PASSWORD_LENGTH}+ characters and match"); return
            try:
                _, recovery = self.vault.change_master_password(first.get())
                win.destroy(); self.show_recovery_key_screen(recovery, "Password changed successfully.")
            except VaultError as exc: messagebox.showerror("Error", str(exc))
        ctk.CTkButton(win, text="Change password", command=change).pack(pady=15)

    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    PasswordGeneratorApp().run()
