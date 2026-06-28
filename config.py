"""
CyberGuard Configuration
========================
All environment-specific settings live here.
For MySQL: change DATABASE_URL to mysql+pymysql://user:pass@host/dbname
"""

import os
from datetime import timedelta

# ── Database ─────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///cyberguard.db")

# ── Security ──────────────────────────────────────────────────────────────────
SECRET_KEY       = os.environ.get("SECRET_KEY", "cg-dev-secret-change-in-production!")
SESSION_LIFETIME = timedelta(minutes=30)

# ── Email Encryption (Fernet AES-128 symmetric) ───────────────────────────────
# This key encrypts emails stored in the database.
# If not set, a dev key is used — CHANGE THIS IN PRODUCTION.
# Generate your own: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY = os.environ.get(
    "ENCRYPTION_KEY",
    "mUj30dXeuoXrYm5uSVjvLLwU9jE-gtIgLeaSnpqI41A="   # dev default — replace in prod
)

# ── Login Protection ──────────────────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES    = 15

# ── Real Email (SMTP) ─────────────────────────────────────────────────────────
# Leave MAIL_USERNAME blank → OTPs print to terminal (dev mode)
# Set it to your Gmail → OTPs go to real inboxes
#
# HOW TO SET UP GMAIL:
#   1. Google Account → Security → Turn on 2-Step Verification
#   2. Search "App passwords" → create one → copy 16-char code
#   3. Put that code in MAIL_PASSWORD below (or in your .env file)
MAIL_SERVER   = os.environ.get("MAIL_SERVER",   "smtp.gmail.com")
MAIL_PORT     = int(os.environ.get("MAIL_PORT", 587))
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")   # ← your Gmail here
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")   # ← 16-char app password
MAIL_FROM     = os.environ.get("MAIL_FROM",     "noreply@cyberguard.local")

# ── OTP ───────────────────────────────────────────────────────────────────────
OTP_EXPIRY_MINUTES = 10

# ── Application ───────────────────────────────────────────────────────────────
APP_NAME    = "CyberGuard"
APP_VERSION = "2.1.0"
