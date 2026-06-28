╔══════════════════════════════════════════════════════════════╗
║          CyberGuard v2.1 – Secure Auth Platform              ║
║          Diploma Computer Engineering – Final Project        ║
╚══════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 STEP 1 — INSTALL PYTHON (if not already)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Download Python 3.11+ from https://python.org
  ✅ Check "Add Python to PATH" during install (Windows)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 STEP 2 — INSTALL REQUIRED PACKAGES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Open a terminal / command prompt in this folder and run:

    pip install flask cryptography

  (That is ALL you need — no other packages required)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 STEP 3 — RUN THE PROJECT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    python run.py

  Then open your browser at: http://127.0.0.1:5000

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 DEFAULT ADMIN LOGIN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Email    : admin@cyberguard.com
  Password : Admin@1234!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 OTP IN DEV MODE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OTPs and verification links print in the TERMINAL window.
  Look for the box starting with ┌────...
  Copy the 6-digit OTP and paste it on the /verify-otp page.

  To send REAL emails: open config.py and fill in:
    MAIL_USERNAME = "your@gmail.com"
    MAIL_PASSWORD = "xxxx xxxx xxxx xxxx"  ← Gmail App Password

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PAGES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  /              Home page (hero + features)
  /register      Create account (CAPTCHA + password meter)
  /login         Login (CAPTCHA + OTP 2FA)
  /verify-otp    OTP entry page
  /forgot-password Password reset via email
  /dashboard     Login history audit table
  /profile       Your account details
  /security      Security score + alerts
  /admin         Admin panel (users + blog + encryption viewer)
  /blog          Security blog with categories
  /about         Project overview
  /docs          All 10 security features explained (viva prep)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PROJECT FILES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  run.py         ← START HERE
  app.py         All routes and logic
  config.py      Settings (email, encryption key, limits)
  models.py      Database schema + seeding
  security.py    Password hashing, email encryption, OTP, CAPTCHA
  mailer.py      Email sending (SMTP or terminal fallback)
  requirements.txt
  templates/     All HTML pages (16 files)
  database/      MySQL schema for production use
