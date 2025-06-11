# Recon Tab Walker – Web Reconnaissance Firefox Extension

![Firefox Extension CI](https://github.com/abatsakidis/Recon-Tab-Walker-Web-Reconnaissance-Firefox-Extension/actions/workflows/ci.yml/badge.svg)

**Recon Tab Walker** is a lightweight, privacy-aware Firefox extension designed to automate passive web reconnaissance and surface-level vulnerability scanning on visited websites. Ideal for penetration testers, bug bounty hunters, and security enthusiasts, this tool runs directly in the browser without external dependencies or intrusive scanning.

## 🚀 Features

- 🛡️ **Form Analysis**  
  Detects all forms on the page and checks for missing CSRF tokens, insecure input fields, and inline JavaScript handlers.

- 🔍 **CMS Fingerprinting**  
  Identifies common CMS platforms (e.g., WordPress, Joomla, Drupal, Magento, etc.) based on known page patterns and file paths.

- 🧬 **Vulnerable JavaScript Library Detection**  
  Alerts if known vulnerable libraries (like jQuery, AngularJS) are loaded on the page.

- 🔓 **Exposed Endpoints Check**  
  Scans for potentially exposed or sensitive API and admin URLs such as `/api/`, `/wp-json/`, `/admin/`, `/.env`, etc.

- 🔐 **SSL/TLS Usage Check**  
  Verifies whether the site is served over HTTPS.

- 🔐 **Subresource Integrity (SRI) Check**  
  Detects external scripts/styles loaded without the `integrity` attribute, which can lead to content tampering.

- 🧱 **Default Admin Panel Check**  
  Looks for default login/admin panel pages (`/admin`, `/wp-admin`, `/login`, etc.).

- ⚠️ **Visual Highlighting of Vulnerable Elements**  
  Forms or inputs that appear vulnerable are outlined in red for easy visibility.

- 📜 **Detailed Report Generation**  
  Consolidated and formatted output shown within the extension popup after scanning.

## 📦 Installation (Manual)

1. Clone or download this repository and unzip it.
2. Open Firefox and navigate to `about:debugging`.
3. Click **"This Firefox"** on the sidebar.
4. Click **"Load Temporary Add-on"**.
5. Select the `manifest.json` file from the extension folder.

> 💡 To persist the extension, consider packaging and signing it for distribution via [Firefox Add-ons](https://addons.mozilla.org/).

## 🔧 Usage

1. Click on the **Recon Tab Walker** icon in the toolbar.
2. Press **"Run Recon"** on any tab you wish to analyze.
3. A full security report will be generated after a few seconds.

## 🧠 Limitations

- This extension performs **passive checks only**. It does not attempt intrusion or brute-force attacks.
- Only known static CMS and library fingerprints are detected. Custom systems may not be recognized.
- Not intended to replace professional vulnerability scanners, but rather to complement them in the reconnaissance phase.

## 📜 License

MIT License


