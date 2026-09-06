import customtkinter as ctk
import random
import string
import pyperclip
import json
import os
import secrets
import hashlib
import base64
import time
import tempfile
from datetime import datetime, timedelta
from tkinter import messagebox, filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class PasswordVault:
    def __init__(self):
        self.vault_file = "password_vault.dat"
        self.salt = None
        self.master_hash = None
        self.recovery_hash = None
        self.key = None
        self.passwords = []
        self._encrypted_blob = None
        self._recovery_encrypted_key = None
        self.load_vault()

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def generate_recovery_key(self) -> str:
        alphabet = string.ascii_uppercase + string.digits
        parts = [''.join(secrets.choice(alphabet) for _ in range(4)) for _ in range(6)]
        return "-".join(parts)

    def set_master_password(self, password: str) -> tuple[bool, str]:
        if not (1 <= len(password) <= 4 and password.isdigit()):
            return False, ""

        self.salt = secrets.token_bytes(16)
        self.key = self._derive_key(password, self.salt)

        self.master_hash = hashlib.sha256(
            (password + base64.b64encode(self.salt).decode()).encode()
        ).hexdigest()

        recovery_key = self.generate_recovery_key()
        recovery_derived = self._derive_key(recovery_key, self.salt)

        self.recovery_hash = hashlib.sha256(
            (recovery_key + base64.b64encode(self.salt).decode()).encode()
        ).hexdigest()

        f_recovery = Fernet(recovery_derived)
        self._recovery_encrypted_key = f_recovery.encrypt(self.key).decode()

        self.passwords = []
        self.save_vault()
        return True, recovery_key

    def verify_pin(self, password: str) -> bool:
        if not self.salt or not self.master_hash:
            return False

        check = hashlib.sha256(
            (password + base64.b64encode(self.salt).decode()).encode()
        ).hexdigest()

        if check == self.master_hash:
            self.key = self._derive_key(password, self.salt)
            self._decrypt_passwords()
            return True
        return False

    def verify_and_unlock(self, password: str) -> bool:
        if not self.salt or not self.master_hash:
            return False

        check = hashlib.sha256(
            (password + base64.b64encode(self.salt).decode()).encode()
        ).hexdigest()

        if check != self.master_hash:
            return False

        self.key = self._derive_key(password, self.salt)
        return self._decrypt_passwords()

    def verify_recovery_key(self, recovery_key: str) -> bool:
        if not self.salt or not self.recovery_hash:
            return False

        check = hashlib.sha256(
            (recovery_key + base64.b64encode(self.salt).decode()).encode()
        ).hexdigest()

        if check != self.recovery_hash:
            return False

        try:
            recovery_derived = self._derive_key(recovery_key, self.salt)
            f_recovery = Fernet(recovery_derived)
            self.key = f_recovery.decrypt(self._recovery_encrypted_key.encode())
            return self._decrypt_passwords()
        except Exception:
            self.key = None
            return False

    def _decrypt_passwords(self) -> bool:
        try:
            if not self._encrypted_blob:
                self.passwords = []
                return True
            f = Fernet(self.key)
            decrypted = f.decrypt(base64.b64decode(self._encrypted_blob))
            self.passwords = json.loads(decrypted.decode())
            return True
        except Exception:
            self.key = None
            self.passwords = []
            return False

    def change_master_password(self, new_password: str) -> bool:
        if not (1 <= len(new_password) <= 4 and new_password.isdigit()) or not self.key:
            return False

        self.master_hash = hashlib.sha256(
            (new_password + base64.b64encode(self.salt).decode()).encode()
        ).hexdigest()

        new_key = self._derive_key(new_password, self.salt)
        f_new = Fernet(new_key)
        plain = json.dumps(self.passwords).encode()
        self._encrypted_blob = base64.b64encode(f_new.encrypt(plain)).decode()
        self.key = new_key
        self.save_vault()
        return True

    def save_vault(self):
        """Persist the encrypted vault atomically so interrupted writes do not corrupt it."""
        if not self.salt:
            return
        temp_path = None
        try:
            data = {
                "salt": base64.b64encode(self.salt).decode(),
                "master_hash": self.master_hash,
                "recovery_hash": self.recovery_hash,
                "recovery_encrypted_key": self._recovery_encrypted_key,
            }
            if self.key is not None:
                f = Fernet(self.key)
                plain = json.dumps(self.passwords).encode()
                data["encrypted_data"] = base64.b64encode(f.encrypt(plain)).decode()
            elif self._encrypted_blob:
                data["encrypted_data"] = self._encrypted_blob

            vault_dir = os.path.dirname(os.path.abspath(self.vault_file))
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=vault_dir, prefix=".password_vault-", suffix=".tmp", delete=False
            ) as f:
                temp_path = f.name
                f.write(json.dumps(data).encode())
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.vault_file)
        except Exception as e:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
            raise Exception(f"Vault save failed: {str(e)}")

    def load_vault(self):
        if not os.path.exists(self.vault_file):
            return
        try:
            with open(self.vault_file, "rb") as f:
                data = json.loads(f.read().decode())
            self.salt = base64.b64decode(data["salt"])
            self.master_hash = data.get("master_hash")
            self.recovery_hash = data.get("recovery_hash")
            self._recovery_encrypted_key = data.get("recovery_encrypted_key")
            self._encrypted_blob = data.get("encrypted_data")
            self.passwords = []
            self.key = None
        except Exception:
            pass

    def lock(self):
        self.key = None
        self.passwords = []

    def add_password(self, platform, username, password, notes="", category="General", tags="", expiry_days=0):
        entry = {
            "id": secrets.token_hex(8),
            "platform": platform,
            "username": username,
            "password": password,
            "notes": notes,
            "category": category,
            "tags": tags,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "expiry": (datetime.now() + timedelta(days=expiry_days)).strftime("%Y-%m-%d") if expiry_days > 0 else ""
        }
        self.passwords.append(entry)
        self.save_vault()
        return True

    def get_all(self):
        return self.passwords.copy()

    def delete_password(self, entry_id):
        self.passwords = [p for p in self.passwords if p["id"] != entry_id]
        self.save_vault()
        return True


class PasswordGeneratorApp:
    def __init__(self):
        self.window = ctk.CTk()
        self.window.title("🔐 Password Manager Pro")
        self.window.geometry("920x780")
        self.window.minsize(800, 650)
        self.window.resizable(True, True)

        self.vault = PasswordVault()
        self.vault_unlocked = False
        self.current_theme = "dark"
        self.current_tab = "🔑 Generator"
        self.last_activity = datetime.now()
        self.clipboard_clear_after = 30
        self.recent_platforms = []
        self.password_visible = False

        self.center_window()
        self.create_widgets()

        if not self.vault.master_hash:
            self.show_setup_vault()
        else:
            self.update_saved_display()
            self.window.after(0, lambda: self.unlock_vault_with_pin(startup=True))

    def center_window(self):
        self.window.update_idletasks()
        w, h = 920, 780
        x = (self.window.winfo_screenwidth() // 2) - (w // 2)
        y = (self.window.winfo_screenheight() // 2) - (h // 2)
        self.window.geometry(f"{w}x{h}+{x}+{y}")

    def register_activity(self, event=None):
        self.last_activity = datetime.now()

    def show_setup_vault(self):
        win = ctk.CTkToplevel(self.window)
        win.title("Setup Master Password")
        win.geometry("420x340")
        win.resizable(False, False)
        win.transient(self.window)
        win.grab_set()

        ctk.CTkLabel(win, text="🔐 Create Master PIN", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=18)
        ctk.CTkLabel(win, text="Must be 1 to 4 digits only (e.g. 1234)", font=ctk.CTkFont(size=13)).pack()

        pw = ctk.CTkEntry(win, placeholder_text="Enter PIN (1-4 digits)", show="*", width=320, height=40)
        pw.pack(pady=10)
        cf = ctk.CTkEntry(win, placeholder_text="Confirm PIN", show="*", width=320, height=40)
        cf.pack(pady=5)

        def create():
            p1, p2 = pw.get(), cf.get()
            if not (1 <= len(p1) <= 4 and p1.isdigit()):
                messagebox.showerror("Error", "Master PIN must be between 1 and 4 digits!")
                return
            if p1 != p2:
                messagebox.showerror("Error", "Passwords do not match!")
                return

            success, recovery_key = self.vault.set_master_password(p1)
            if success:
                win.destroy()
                self.show_recovery_key_screen(recovery_key)
            else:
                messagebox.showerror("Error", "Failed to create vault")

        ctk.CTkButton(win, text="Create Vault", command=create, height=42,
                      font=ctk.CTkFont(size=14, weight="bold")).pack(pady=15)
        ctk.CTkLabel(win, text="⚠️ Remember this PIN. It cannot be recovered without Recovery Key!",
                     text_color="#ffaa00").pack()

    def show_recovery_key_screen(self, recovery_key: str):
        win = ctk.CTkToplevel(self.window)
        win.title("⚠️ Recovery Key - Important")
        win.geometry("560x520")
        win.resizable(False, False)
        win.transient(self.window)
        win.grab_set()

        win.update_idletasks()
        x = (win.winfo_screenwidth() // 2) - 280
        y = (win.winfo_screenheight() // 2) - 260
        win.geometry(f"560x520+{x}+{y}")

        ctk.CTkLabel(win, text="⚠️ RECOVERY KEY",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color="#ff4444").pack(pady=(20, 5))

        ctk.CTkLabel(win,
                     text="This key is extremely important!\nIf you forget your master PIN, only this key\ncan recover your passwords.",
                     font=ctk.CTkFont(size=14),
                     justify="center").pack(pady=5)

        key_frame = ctk.CTkFrame(win, fg_color="#1a1a1a", corner_radius=10)
        key_frame.pack(pady=15, padx=30, fill="x")

        ctk.CTkLabel(key_frame,
                     text=recovery_key,
                     font=ctk.CTkFont(size=18, weight="bold", family="Consolas"),
                     text_color="#00ff88").pack(pady=15)

        def copy_key():
            pyperclip.copy(recovery_key)
            copy_btn.configure(text="✓ Copied!")
            self.window.after(2000, lambda: copy_btn.configure(text="📋 Copy Recovery Key"))

        copy_btn = ctk.CTkButton(win, text="📋 Copy Recovery Key", width=220, height=40,
                                 command=copy_key, fg_color="#2b6e4e")
        copy_btn.pack(pady=5)

        warning_text = (
            "• Do not store this key online\n"
            "• Write it down or print it and keep it somewhere secure\n"
            "• Never share this key\n"
            "• If you lose this key, your passwords cannot be recovered\n"
            "• This key will not be shown again after closing this screen"
        )
        ctk.CTkLabel(win, text=warning_text,
                     font=ctk.CTkFont(size=13),
                     text_color="#ffaa00",
                     justify="left").pack(pady=10)

        def confirm_saved():
            if messagebox.askyesno("Confirm",
                                   "Have you saved the recovery key securely?\n\n"
                                   "Without this key, your passwords cannot be recovered later."):
                win.destroy()
                self.status_label.configure(
                    text="🔐 Vault created • Keep your recovery key safe",
                    text_color="#44ff44"
                )

        ctk.CTkButton(win, text="✅ I saved the key", width=240, height=45,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=confirm_saved).pack(pady=15)

    def show_recovery_flow(self):
        win = ctk.CTkToplevel(self.window)
        win.title("Recover Vault")
        win.geometry("420x400")
        win.resizable(False, False)
        win.transient(self.window)
        win.grab_set()

        ctk.CTkLabel(win, text="🔑 Recover with Recovery Key",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)

        ctk.CTkLabel(win, text="Enter your recovery key").pack()
        rec_entry = ctk.CTkEntry(win, placeholder_text="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX",
                                 width=320, height=40)
        rec_entry.pack(pady=8)

        ctk.CTkLabel(win, text="Set a new master PIN").pack(pady=(10, 0))
        new_pw = ctk.CTkEntry(win, placeholder_text="New master PIN (1-4 digits)", show="*", width=320, height=38)
        new_pw.pack(pady=5)
        conf_pw = ctk.CTkEntry(win, placeholder_text="Confirm new PIN", show="*", width=320, height=38)
        conf_pw.pack(pady=5)

        def do_recover():
            recovery_key = rec_entry.get().strip().upper()
            p1 = new_pw.get()
            p2 = conf_pw.get()

            if not (1 <= len(p1) <= 4 and p1.isdigit()):
                messagebox.showerror("Error", "New PIN must be between 1 and 4 digits")
                return
            if p1 != p2:
                messagebox.showerror("Error", "Passwords do not match")
                return

            if self.vault.verify_recovery_key(recovery_key):
                if self.vault.change_master_password(p1):
                    self.vault_unlocked = True
                    win.destroy()
                    self.vault_status_label.configure(text="🔓 Unlocked", text_color="#44ff44")
                    self.update_saved_display()
                    messagebox.showinfo("Success", "Vault recovered successfully!\nNew Master Password set.")
                else:
                    messagebox.showerror("Error", "Failed to set new password")
            else:
                messagebox.showerror("Error", "Invalid Recovery Key")

        ctk.CTkButton(win, text="Recover Vault", height=42, command=do_recover,
                      font=ctk.CTkFont(size=14, weight="bold")).pack(pady=15)

    def lock_vault(self):
        self.vault.lock()
        self.vault_unlocked = False
        self.vault_status_label.configure(text="🔒 Locked", text_color="#ff4444")
        self.password_entry.configure(show="*")
        self.password_visible = False
        self.update_saved_display()

    def unlock_vault_with_pin(self, callback=None, startup=False):
        """Vault unlock – used only when entering Vault tab"""
        if self.vault_unlocked:
            if callback:
                callback()
            return

        win = ctk.CTkToplevel(self.window)
        win.title("🔓 Unlock Vault")
        win.geometry("380x240")
        win.resizable(False, False)
        win.transient(self.window)
        win.grab_set()

        ctk.CTkLabel(win, text="🔐 Enter Master PIN",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)

        entry = ctk.CTkEntry(win, placeholder_text="Enter PIN (1-4 digits)", show="*", width=280, height=40)
        entry.pack(pady=10)
        entry.focus()

        error_label = ctk.CTkLabel(win, text="", text_color="#ff4444")
        error_label.pack()

        def check():
            pin = entry.get()
            if not (1 <= len(pin) <= 4 and pin.isdigit()):
                error_label.configure(text="PIN must be 1-4 digits only!")
                return

            if self.vault.verify_pin(pin):
                self.vault_unlocked = True
                self.vault_status_label.configure(text="🔓 Unlocked", text_color="#44ff44")
                win.destroy()
                self.update_saved_display()
                self.status_label.configure(text="Vault unlocked", text_color="#44ff44")
                if callback:
                    callback()
            else:
                error_label.configure(text="❌ Incorrect PIN!")
                entry.delete(0, "end")
                entry.focus()

        ctk.CTkButton(win, text="Unlock", command=check, height=40, width=150,
                      font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)
        entry.bind("<Return>", lambda e: check())

        ctk.CTkButton(win, text="Forgot PIN? Use Recovery Key",
                      fg_color="transparent", text_color="#88aaff",
                      command=lambda: [win.destroy(), self.show_recovery_flow()]).pack(pady=5)

        def cancel():
            win.destroy()
            if not self.vault_unlocked:
                self.tabview.set("🔑 Generator")
                self.current_tab = "🔑 Generator"
                self.status_label.configure(
                    text="Vault remains locked until the PIN is verified",
                    text_color="#ffaa00"
                )

        win.protocol("WM_DELETE_WINDOW", cancel)

    def on_tab_change(self):
        current = self.tabview.get()
        if self.current_tab == "💾 Vault" and current != "💾 Vault":
            if self.vault_unlocked:
                self.lock_vault()
                self.status_label.configure(text="🔒 Vault locked (left vault tab)", text_color="#ffaa00")
        if current == "💾 Vault":
            self.unlock_vault_with_pin()
        self.current_tab = current

    def create_widgets(self):
        self.window.bind("<Any-KeyPress>", self.register_activity)
        self.window.bind("<Any-Button>", self.register_activity)

        top = ctk.CTkFrame(self.window, height=50, corner_radius=0)
        top.pack(fill="x")
        top.pack_propagate(False)

        ctk.CTkLabel(top, text="🔐 Password Manager Pro",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(side="left", padx=20)

        self.theme_btn = ctk.CTkButton(top, text="🌙 Dark", width=90, command=self.toggle_theme)
        self.theme_btn.pack(side="right", padx=10)

        self.vault_status_label = ctk.CTkLabel(top, text="🔒 Locked",
                                               font=ctk.CTkFont(size=13, weight="bold"),
                                               text_color="#ff4444")
        self.vault_status_label.pack(side="right", padx=10)

        self.tabview = ctk.CTkTabview(self.window, width=880, height=680,
                                       command=self.on_tab_change)
        self.tabview.pack(pady=10, padx=15, fill="both", expand=True)

        self.tabview.add("🔑 Generator")
        self.tabview.add("💾 Vault")
        self.tabview.add("⚙️ Settings")

        self.build_generator_tab()
        self.build_vault_tab()
        self.build_settings_tab()

        status_frame = ctk.CTkFrame(self.window, height=32, corner_radius=0)
        status_frame.pack(fill="x", side="bottom")
        self.status_label = ctk.CTkLabel(status_frame, text="Ready", font=ctk.CTkFont(size=12))
        self.status_label.pack(side="left", padx=15)

    def toggle_theme(self):
        if self.current_theme == "dark":
            ctk.set_appearance_mode("light")
            self.current_theme = "light"
            self.theme_btn.configure(text="☀️ Light")
        else:
            ctk.set_appearance_mode("dark")
            self.current_theme = "dark"
            self.theme_btn.configure(text="🌙 Dark")

    def build_generator_tab(self):
        tab = self.tabview.tab("🔑 Generator")

        disp = ctk.CTkFrame(tab)
        disp.pack(fill="x", padx=15, pady=12)

        self.password_var = ctk.StringVar(value="Click Generate")
        self.password_entry = ctk.CTkEntry(disp, textvariable=self.password_var,
                                           font=ctk.CTkFont(size=18), height=48, state="readonly")
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(10, 5), pady=10)

        btn_f = ctk.CTkFrame(disp, fg_color="transparent")
        btn_f.pack(side="right", padx=10)
        self.copy_btn = ctk.CTkButton(btn_f, text="📋 Copy", width=80, command=self.copy_password)
        self.copy_btn.pack(side="left", padx=3)
        self.eye_btn = ctk.CTkButton(btn_f, text="👁️", width=40, command=self.toggle_visibility)
        self.eye_btn.pack(side="left", padx=3)

        self.strength_label = ctk.CTkLabel(tab, text="Strength: —", font=ctk.CTkFont(size=14, weight="bold"))
        self.strength_label.pack(pady=(0, 2))
        self.strength_bar = ctk.CTkProgressBar(tab, width=450, height=12)
        self.strength_bar.pack(pady=4)
        self.strength_bar.set(0)
        self.strength_feedback = ctk.CTkLabel(tab, text="", font=ctk.CTkFont(size=12), text_color="#aaaaaa")
        self.strength_feedback.pack()

        opt = ctk.CTkFrame(tab)
        opt.pack(fill="x", padx=15, pady=10)

        left = ctk.CTkFrame(opt, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=10)

        ctk.CTkLabel(left, text="Settings", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w")

        lf = ctk.CTkFrame(left, fg_color="transparent")
        lf.pack(fill="x", pady=6)
        ctk.CTkLabel(lf, text="Length").pack(side="left")
        self.length_var = ctk.IntVar(value=16)
        ctk.CTkSlider(lf, from_=8, to=64, variable=self.length_var,
                      command=lambda v: self.len_label.configure(text=str(int(v)))).pack(side="left", fill="x", expand=True, padx=8)
        self.len_label = ctk.CTkLabel(lf, text="16", width=30)
        self.len_label.pack(side="right")

        self.upper_v = ctk.BooleanVar(value=True)
        self.lower_v = ctk.BooleanVar(value=True)
        self.digit_v = ctk.BooleanVar(value=True)
        self.special_v = ctk.BooleanVar(value=True)
        self.exclude_v = ctk.BooleanVar(value=True)
        self.passphrase_v = ctk.BooleanVar(value=False)

        for text, var in [("Uppercase", self.upper_v), ("Lowercase", self.lower_v),
                          ("Digits", self.digit_v), ("Special", self.special_v)]:
            ctk.CTkCheckBox(left, text=text, variable=var).pack(anchor="w", pady=1)
        ctk.CTkCheckBox(left, text="Exclude similar (il1Lo0O)", variable=self.exclude_v).pack(anchor="w", pady=1)
        ctk.CTkCheckBox(left, text="✨ Generate Passphrase (memorable)", variable=self.passphrase_v).pack(anchor="w", pady=4)

        right = ctk.CTkFrame(opt, fg_color="transparent")
        right.pack(side="right", fill="both", expand=True, padx=10)

        ctk.CTkLabel(right, text="Save Info", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w")

        self.platform_var = ctk.StringVar(value="General")
        platforms = ["General", "Facebook", "Instagram", "WhatsApp", "Telegram", "TikTok",
                     "YouTube", "Twitter/X", "Gmail", "Outlook", "Banking", "Netflix",
                     "Spotify", "Discord", "GitHub", "Work", "Personal"]
        ctk.CTkLabel(right, text="Platform").pack(anchor="w")
        ctk.CTkOptionMenu(right, values=platforms, variable=self.platform_var, width=200).pack(anchor="w", pady=2)

        self.recent_frame = ctk.CTkFrame(right, fg_color="transparent")
        self.recent_frame.pack(fill="x", pady=4)
        ctk.CTkLabel(self.recent_frame, text="Recent:", font=ctk.CTkFont(size=12)).pack(side="left")

        self.username_var = ctk.StringVar()
        ctk.CTkLabel(right, text="Username / Email").pack(anchor="w", pady=(6, 0))
        ctk.CTkEntry(right, textvariable=self.username_var, placeholder_text="username@email.com", width=220).pack(anchor="w")

        self.notes_var = ctk.StringVar()
        ctk.CTkLabel(right, text="Notes").pack(anchor="w", pady=(6, 0))
        ctk.CTkEntry(right, textvariable=self.notes_var, placeholder_text="optional", width=220).pack(anchor="w")

        self.category_var = ctk.StringVar(value="General")
        ctk.CTkLabel(right, text="Category").pack(anchor="w", pady=(6, 0))
        ctk.CTkOptionMenu(right, values=["General", "Social", "Banking", "Work", "Personal", "Entertainment", "Shopping"],
                          variable=self.category_var, width=200).pack(anchor="w")

        bf = ctk.CTkFrame(tab, fg_color="transparent")
        bf.pack(pady=12)
        ctk.CTkButton(bf, text="🔑 Generate Password", width=180, height=42, command=self.generate_password,
                      font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=6)
        ctk.CTkButton(bf, text="💾 Save to Vault", width=160, height=42, fg_color="#2b6e4e",
                      command=self.save_to_vault).pack(side="left", padx=6)

    def build_vault_tab(self):
        tab = self.tabview.tab("💾 Vault")

        ctrl = ctk.CTkFrame(tab)
        ctrl.pack(fill="x", padx=15, pady=8)

        ctk.CTkButton(ctrl, text="📤 Export", width=90, command=self.export_vault).pack(side="left", padx=4)
        ctk.CTkButton(ctrl, text="📥 Import", width=90, command=self.import_vault).pack(side="left", padx=4)

        sf = ctk.CTkFrame(tab)
        sf.pack(fill="x", padx=15, pady=4)
        ctk.CTkLabel(sf, text="🔍").pack(side="left", padx=5)
        self.search_var = ctk.StringVar()
        search_e = ctk.CTkEntry(sf, textvariable=self.search_var,
                                placeholder_text="Search platform, username, notes, tags...")
        search_e.pack(side="left", fill="x", expand=True, padx=5)
        search_e.bind("<KeyRelease>", lambda e: self.update_saved_display())

        self.saved_frame = ctk.CTkScrollableFrame(tab, height=500)
        self.saved_frame.pack(fill="both", expand=True, padx=15, pady=8)

    def build_settings_tab(self):
        tab = self.tabview.tab("⚙️ Settings")
        ctk.CTkLabel(tab, text="Settings", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)

        ctk.CTkLabel(tab, text="🔐 Auto-Lock: Vault locks when you leave the Vault tab").pack(pady=5)
        ctk.CTkLabel(tab, text="🔓 Auto-Unlock: Vault unlocks when you enter the Vault tab").pack(pady=5)
        ctk.CTkLabel(tab, text="Master PIN: 1 to 4 digits only").pack(pady=5)
        ctk.CTkLabel(tab, text="Encryption: AES (Fernet) + PBKDF2 390k iterations").pack(pady=5)
        ctk.CTkLabel(tab, text="Recovery Key support enabled").pack(pady=5)

    def generate_password(self):
        self.register_activity()
        if self.passphrase_v.get():
            words = ["apple", "bridge", "cloud", "dragon", "eagle", "forest", "galaxy", "harbor",
                     "island", "jungle", "knight", "lemon", "mountain", "nebula", "ocean", "panda",
                     "quartz", "river", "sunset", "tiger", "umbrella", "valley", "whisper", "xenon",
                     "yellow", "zebra", "anchor", "blossom", "crystal", "diamond"]
            length = max(4, min(8, self.length_var.get() // 4))
            pw = "-".join(random.choice(words) for _ in range(length))
            if self.digit_v.get():
                pw += str(random.randint(10, 99))
        else:
            chars = ""
            if self.upper_v.get(): chars += string.ascii_uppercase
            if self.lower_v.get(): chars += string.ascii_lowercase
            if self.digit_v.get(): chars += string.digits
            if self.special_v.get(): chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
            if self.exclude_v.get():
                for c in "il1Lo0O":
                    chars = chars.replace(c, "")
            if not chars:
                messagebox.showwarning("Warning", "Select at least one character type")
                return
            length = self.length_var.get()
            pw = "".join(secrets.choice(chars) for _ in range(length))

        self.password_var.set(pw)
        self.password_entry.configure(show="*")
        self.password_visible = False
        self.check_strength(pw)

        plat = self.platform_var.get()
        if plat not in self.recent_platforms:
            self.recent_platforms.insert(0, plat)
            self.recent_platforms = self.recent_platforms[:5]
            self.update_recent_buttons()

        self.status_label.configure(text=f"Generated ({len(pw)} chars)", text_color="#44ff44")

    def update_recent_buttons(self):
        for w in self.recent_frame.winfo_children()[1:]:
            w.destroy()
        for p in self.recent_platforms:
            ctk.CTkButton(self.recent_frame, text=p, width=70, height=24, font=ctk.CTkFont(size=11),
                          command=lambda x=p: self.platform_var.set(x)).pack(side="left", padx=2)

    def check_strength(self, pw):
        score = 0
        if len(pw) >= 12: score += 2
        elif len(pw) >= 8: score += 1

        has_u = any(c.isupper() for c in pw)
        has_l = any(c.islower() for c in pw)
        has_d = any(c.isdigit() for c in pw)
        has_s = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pw)
        score += sum([has_u, has_l, has_d, has_s])
        if len(set(pw)) > len(pw) * 0.7: score += 1

        pct = min(score / 8, 1.0)
        self.strength_bar.set(pct)

        if pct < 0.3:
            self.strength_label.configure(text="🔴 Very Weak", text_color="#ff4444")
            self.strength_feedback.configure(text="Add length + more character types")
        elif pct < 0.5:
            self.strength_label.configure(text="🟠 Weak", text_color="#ff8800")
            self.strength_feedback.configure(text="Try longer password or add symbols")
        elif pct < 0.7:
            self.strength_label.configure(text="🟡 Medium", text_color="#ffcc00")
            self.strength_feedback.configure(text="Decent, but can be stronger")
        elif pct < 0.9:
            self.strength_label.configure(text="🟢 Strong", text_color="#44ff44")
            self.strength_feedback.configure(text="Good password")
        else:
            self.strength_label.configure(text="💪 Excellent", text_color="#00ff88")
            self.strength_feedback.configure(text="Excellent security")

    # ==================== Eye Icon ====================
    def toggle_visibility(self):
        pw = self.password_var.get()
        if not pw or pw == "Click Generate":
            return

        if self.password_visible:
            self.password_entry.configure(show="*")
            self.password_visible = False
            self.status_label.configure(text="Password hidden", text_color="#ffaa00")
        else:
            self.password_entry.configure(show="")
            self.password_visible = True
            self.status_label.configure(text="👁️ Password visible (10 seconds)", text_color="#44ff44")
            self.window.after(10000, self.hide_password_after_10s)

    def hide_password_after_10s(self):
        if self.password_visible:
            self.password_entry.configure(show="*")
            self.password_visible = False
            self.status_label.configure(text="Password hidden (10s expired)", text_color="#ffaa00")

    # ==================== Copy Button ====================
    def copy_password(self):
        pw = self.password_var.get()
        if not pw or pw == "Click Generate":
            return

        pyperclip.copy(pw)
        self.status_label.configure(text="📋 Copied (clears in 30s)", text_color="#44ff44")
        self.copy_btn.configure(text="✅ Copied!")
        self.window.after(2000, lambda: self.copy_btn.configure(text="📋 Copy"))
        self.window.after(self.clipboard_clear_after * 1000, lambda: pyperclip.copy(""))

    # ==================== Save to Vault ====================
    def save_to_vault(self):
        pw = self.password_var.get()
        if not pw or pw == "Click Generate":
            messagebox.showinfo("Info", "Generate a password first")
            return

        def do_save():
            try:
                username = self.username_var.get() or "user"
                self.vault.add_password(
                    platform=self.platform_var.get(),
                    username=username,
                    password=pw,
                    notes=self.notes_var.get(),
                    category=self.category_var.get()
                )
                self.update_saved_display()
                self.status_label.configure(text="💾 Saved to vault", text_color="#44ff44")
                messagebox.showinfo("Saved", f"Saved for {self.platform_var.get()} ({username})")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save password:\n{str(e)}")

        win = ctk.CTkToplevel(self.window)
        win.title("🔐 Save Password")
        win.geometry("380x220")
        win.resizable(False, False)
        win.transient(self.window)
        win.grab_set()

        ctk.CTkLabel(win, text="Enter Master PIN to save",
                     font=ctk.CTkFont(size=16, weight="bold")).pack(pady=18)

        entry = ctk.CTkEntry(win, placeholder_text="PIN (1-4 digits)", show="*", width=280, height=38)
        entry.pack(pady=8)
        entry.focus()

        error_label = ctk.CTkLabel(win, text="", text_color="#ff4444")
        error_label.pack()

        def check():
            pin = entry.get()
            if not (1 <= len(pin) <= 4 and pin.isdigit()):
                error_label.configure(text="PIN must be 1-4 digits only!")
                return

            try:
                if self.vault.verify_and_unlock(pin):
                    self.vault_unlocked = True
                    self.vault_status_label.configure(text="🔓 Unlocked", text_color="#44ff44")
                    win.destroy()
                    do_save()
                else:
                    error_label.configure(text="❌ Incorrect PIN!")
                    entry.delete(0, "end")
                    entry.focus()
            except Exception as e:
                messagebox.showerror("Error", f"PIN verification failed:\n{str(e)}")

        ctk.CTkButton(win, text="Save", command=check, height=38, width=120,
                      font=ctk.CTkFont(size=14, weight="bold")).pack(pady=8)
        entry.bind("<Return>", lambda e: check())

    # ==================== Vault display ====================
    def update_saved_display(self):
        for w in self.saved_frame.winfo_children():
            w.destroy()

        if not self.vault_unlocked:
            ctk.CTkLabel(self.saved_frame, text="🔒 Vault is locked\nGo to Vault tab to unlock",
                         font=ctk.CTkFont(size=15), text_color="#888888").pack(pady=60)
            return

        entries = self.vault.get_all()
        q = self.search_var.get().lower()
        if q:
            entries = [e for e in entries if
                       q in e["platform"].lower() or
                       q in e.get("username", "").lower() or
                       q in e.get("notes", "").lower() or
                       q in e.get("tags", "").lower() or
                       q in e.get("category", "").lower()]

        if not entries:
            ctk.CTkLabel(self.saved_frame, text="No passwords found", text_color="#888888").pack(pady=40)
            return

        for e in sorted(entries, key=lambda x: x["updated"], reverse=True):
            card = ctk.CTkFrame(self.saved_frame)
            card.pack(fill="x", pady=5, padx=5)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=10, pady=4)
            ctk.CTkLabel(top, text=f"{e['platform']}", font=ctk.CTkFont(size=15, weight="bold")).pack(side="left")
            ctk.CTkLabel(top, text=f"  •  {e.get('category', '')}", text_color="#88aaff").pack(side="left")
            ctk.CTkLabel(top, text=e.get("username", ""), text_color="#aaaaaa").pack(side="right")

            mid = ctk.CTkFrame(card, fg_color="transparent")
            mid.pack(fill="x", padx=10, pady=2)

            masked = "•" * min(18, len(e["password"]))
            pw_lbl = ctk.CTkLabel(mid, text=masked, font=ctk.CTkFont(size=13))
            pw_lbl.pack(side="left")
            pw_visible_state = [False]

            def make_toggle(p=e["password"], lbl=pw_lbl, mask=masked, state=pw_visible_state):
                def toggle():
                    if not self.vault_unlocked:
                        messagebox.showinfo("Info", "Vault is locked!")
                        return
                    if state[0]:
                        lbl.configure(text=mask)
                        state[0] = False
                        self.status_label.configure(text="Password hidden", text_color="#ffaa00")
                    else:
                        lbl.configure(text=p)
                        state[0] = True
                        self.status_label.configure(text="👁️ Password visible (10 seconds)", text_color="#44ff44")
                        self.window.after(10000, lambda: [lbl.configure(text=mask),
                                                          state.__setitem__(0, False),
                                                          self.status_label.configure(text="Password hidden (10s expired)", text_color="#ffaa00")])
                return toggle

            ctk.CTkButton(mid, text="👁️", width=36, height=26, command=make_toggle()).pack(side="left", padx=4)

            def make_copy(p=e["password"]):
                def do_copy():
                    if not self.vault_unlocked:
                        messagebox.showinfo("Info", "Vault is locked!")
                        return
                    pyperclip.copy(p)
                    self.status_label.configure(text="📋 Password copied (clears in 30s)", text_color="#44ff44")
                    self.window.after(30000, lambda: pyperclip.copy(""))
                return do_copy

            ctk.CTkButton(mid, text="📋 Pass", width=70, height=26, fg_color="#2b6e4e",
                          command=make_copy()).pack(side="left", padx=2)

            def make_user_copy(u=e.get("username", "")):
                def action():
                    if not self.vault_unlocked:
                        messagebox.showinfo("Info", "Vault is locked!")
                        return
                    pyperclip.copy(u)
                    self.status_label.configure(text="📋 Username copied!", text_color="#44ff44")
                return action

            ctk.CTkButton(mid, text="📋 User", width=70, height=26,
                          command=make_user_copy()).pack(side="left", padx=2)

            ctk.CTkButton(mid, text="🗑️", width=36, height=26, fg_color="#8b2f2f",
                          command=lambda i=e["id"]: self.delete_entry(i)).pack(side="right", padx=4)

            if e.get("notes"):
                ctk.CTkLabel(card, text=e["notes"], font=ctk.CTkFont(size=11), text_color="#888888").pack(anchor="w", padx=12)
            if e.get("expiry"):
                ctk.CTkLabel(card, text=f"Expiry: {e['expiry']}", font=ctk.CTkFont(size=11), text_color="#ffaa00").pack(anchor="w", padx=12)

    def delete_entry(self, entry_id):
        if not self.vault_unlocked:
            messagebox.showinfo("Info", "Please unlock the vault first")
            return
        if messagebox.askyesno("Confirm", "Delete this password?"):
            self.vault.delete_password(entry_id)
            self.update_saved_display()

    def export_vault(self):
        if not self.vault_unlocked:
            messagebox.showinfo("Info", "Unlock vault first")
            return
        path = filedialog.asksaveasfilename(defaultextension=".vault", filetypes=[("Vault", "*.vault")])
        if path:
            try:
                with open(self.vault.vault_file, "rb") as f:
                    data = f.read()
                with open(path, "wb") as f:
                    f.write(data)
                messagebox.showinfo("Export", "Vault exported successfully (still encrypted)")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def import_vault(self):
        path = filedialog.askopenfilename(filetypes=[("Vault", "*.vault"), ("All", "*.*")])
        if path:
            if messagebox.askyesno("Import", "This will replace current vault. Continue?"):
                try:
                    import shutil
                    shutil.copy(path, self.vault.vault_file)
                    self.vault = PasswordVault()
                    self.vault_unlocked = False
                    self.lock_vault()
                    messagebox.showinfo("Import", "Vault imported. Please unlock with its master password.")
                except Exception as e:
                    messagebox.showerror("Error", str(e))

    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    app = PasswordGeneratorApp()
    app.run()