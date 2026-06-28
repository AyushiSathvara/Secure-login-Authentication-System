"""
CyberGuard – Security Utilities v2.1
======================================
NEW in this version:
  encrypt_email / decrypt_email  – Fernet AES-128 symmetric encryption
  All existing functions kept intact.
"""

import hashlib, hmac, os, secrets, re, html, base64
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from config import OTP_EXPIRY_MINUTES, LOCKOUT_MINUTES, ENCRYPTION_KEY


# ── Fernet Email Encryption ───────────────────────────────────────────────────
# Fernet = AES-128-CBC + HMAC-SHA256 + timestamp. Built into Python cryptography lib.
# Key must be 32 url-safe base64 bytes (generated once, stored safely).

_fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)


def encrypt_email(email: str) -> str:
    """
    Encrypt a plaintext email using Fernet (AES-128-CBC).
    Returns a base64 token string safe to store in the database.
    Example: "jane@gmail.com" → "gAAAAABl..."  (looks like random gibberish)
    """
    return _fernet.encrypt(email.lower().strip().encode()).decode()


def decrypt_email(token: str) -> str:
    """
    Decrypt a Fernet token back to the original email.
    Used when we need to display or send email to the user.
    """
    try:
        return _fernet.decrypt(token.encode()).decode()
    except Exception:
        return "[decryption error]"


def make_email_lookup(email: str) -> str:
    """
    For database lookups we need a deterministic value (encryption is random each time).
    We store a SHA-256 HMAC of the email as a separate lookup index — never reversible.
    This lets us find 'does this email exist?' without decrypting every row.
    """
    return hmac.new(
        ENCRYPTION_KEY.encode()[:32],
        email.lower().strip().encode(),
        hashlib.sha256
    ).hexdigest()


# ── Password Hashing (Scrypt) ─────────────────────────────────────────────────
def hash_password(password: str) -> str:
    """
    Hash password with Scrypt KDF + 256-bit random salt.
    Stored as: salt_hex$hash_hex
    Scrypt needs 64 MB RAM per attempt — brute-force is economically infeasible.
    """
    salt = os.urandom(32)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + dk.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time comparison prevents timing attacks."""
    try:
        salt_hex, hash_hex = stored_hash.split("$")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# ── Password Strength ─────────────────────────────────────────────────────────
def check_password_strength(password: str) -> dict:
    rules = {
        "length":    len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit":     bool(re.search(r"\d",    password)),
        "special":   bool(re.search(r'[!@#$%^&*(),.?":{}|<>_\-]', password)),
    }
    score = sum(rules.values())
    if score <= 2:   label, css = "Weak",   "danger"
    elif score <= 4: label, css = "Medium", "warning"
    else:            label, css = "Strong", "success"
    return {"rules": rules, "score": score, "label": label, "css": css}


# ── OTP ───────────────────────────────────────────────────────────────────────
def generate_otp() -> tuple:
    otp     = str(secrets.randbelow(900000) + 100000)
    expires = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    return otp, expires


# ── Email Token ───────────────────────────────────────────────────────────────
def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


# ── CAPTCHA ───────────────────────────────────────────────────────────────────
def captcha_generate() -> tuple:
    a, b = secrets.randbelow(10) + 1, secrets.randbelow(10) + 1
    ops = [
        (f"{a} + {b}", a + b),
        (f"{a} × {b}", a * b),
        (f"{max(a,b)} - {min(a,b)}", max(a,b) - min(a,b)),
    ]
    return secrets.choice(ops)


def captcha_verify(answer_str: str, correct: int) -> bool:
    try:
        return int(str(answer_str).strip()) == correct
    except (ValueError, TypeError):
        return False


# ── XSS Sanitise ─────────────────────────────────────────────────────────────
def sanitize(value: str) -> str:
    return html.escape(str(value).strip())


# ── Account Lock ─────────────────────────────────────────────────────────────
def is_account_locked(locked_until_str) -> bool:
    if not locked_until_str:
        return False
    try:
        return datetime.utcnow() < datetime.fromisoformat(str(locked_until_str))
    except ValueError:
        return False


def lockout_until() -> str:
    return (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()


def remaining_lockout(locked_until_str) -> int:
    if not locked_until_str:
        return 0
    try:
        delta = datetime.fromisoformat(str(locked_until_str)) - datetime.utcnow()
        return max(0, int(delta.total_seconds()))
    except ValueError:
        return 0
