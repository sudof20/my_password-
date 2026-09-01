# My Password Vault

A secure password management application designed to run smoothly on mobile devices.

---

## 🛠️ Known Issues & Bugs
- **PIN Lock Bypass Issue:** Canceling or bypassing the initial 4-digit PIN input prompt opens the vault directly without authentication.
- **Data Persistence Issue:** Data is not being saved properly after clicking the "Save" button inside the vault.
- **Language Consistency:** UI text elements need to be fully translated into English.

---

## 🚀 Upcoming Updates & Roadmap
- [ ] Fix the 4-digit PIN authentication check on startup to block unauthorized access.
- [ ] Fix local storage / database save operation on the "Save" button action.
- [ ] Convert all UI labels, prompts, and system messages to English.
- [ ] Enhance mobile responsiveness and touch interactions for android/iOS screens.

---

## 📱 Mobile Setup & Usage Instructions

To run and use this project on your mobile device:

1. **Clone or Download:** Clone this repository or download the ZIP file on your mobile device.
2. **Environment Setup:** 
   - If using HTML/JS: Open the `index.html` file in Chrome/Firefox or any mobile web browser.
   - If using Python/Kivy/Termux: Install **Termux** on Android, clone the repo, install required dependencies, and run the main script.
3. **Usage:** Open the application, set your access PIN, and use the vault interface to store your credentials safely.
