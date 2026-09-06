# My Password Vault

A secure password management application designed to run smoothly on mobile devices.

---

## 🛠️ Security and reliability
- **PIN protection:** Existing vaults require a valid PIN before the vault can be opened. Closing or canceling the PIN prompt leaves the vault locked.
- **Data persistence:** Vault writes are encrypted and committed atomically to reduce the risk of losing data during an interrupted save.
- **Language consistency:** UI labels, prompts, warnings, and recovery instructions are in English.

---

## 🚀 Upcoming Updates & Roadmap
- [x] Require PIN authentication before opening an existing vault.
- [x] Persist vault changes reliably when saving.
- [x] Convert all UI labels, prompts, and system messages to English.
- [ ] Enhance mobile responsiveness and touch interactions for android/iOS screens.

---

## 📱 Mobile Setup & Usage Instructions

To run and use this project on your mobile device:

1. **Clone or Download:** Clone this repository or download the ZIP file on your mobile device.
2. **Environment Setup:** 
   - If using HTML/JS: Open the `index.html` file in Chrome/Firefox or any mobile web browser.
   - If using Python/Kivy/Termux: Install **Termux** on Android, clone the repo, install required dependencies, and run the main script.
3. **Usage:** Open the application, set your access PIN, and use the vault interface to store your credentials safely.
