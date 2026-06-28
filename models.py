"""
CyberGuard – Database Models v2.1
===================================
CHANGES:
  - users.email      → stores Fernet-encrypted ciphertext
  - users.email_hash → HMAC-SHA256 for fast lookup (replaces UNIQUE on email)
  - users.user_count tracking is implicit (COUNT queries)
  - blog_posts table kept and extended
"""

import sqlite3
from config import DATABASE_URL

DB_PATH = DATABASE_URL.replace("sqlite:///", "")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL,
            email           TEXT    NOT NULL,          -- Fernet-encrypted ciphertext
            email_hash      TEXT    NOT NULL UNIQUE,   -- HMAC-SHA256 for lookups
            password_hash   TEXT    NOT NULL,          -- Scrypt hash
            role            TEXT    NOT NULL DEFAULT 'user',
            is_verified     INTEGER NOT NULL DEFAULT 0,
            is_blocked      INTEGER NOT NULL DEFAULT 0,
            login_attempts  INTEGER NOT NULL DEFAULT 0,
            locked_until    TEXT,
            created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS login_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
            login_time  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ip_address  TEXT,
            user_agent  TEXT,
            status      TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS otp_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token       TEXT    NOT NULL,
            purpose     TEXT    NOT NULL DEFAULT 'login',
            expires_at  TEXT    NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS email_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token       TEXT    NOT NULL UNIQUE,
            purpose     TEXT    NOT NULL,
            expires_at  TEXT    NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS blog_posts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT    NOT NULL,
            slug        TEXT    NOT NULL UNIQUE,
            content     TEXT    NOT NULL,
            category    TEXT    NOT NULL DEFAULT 'General',
            author_id   INTEGER REFERENCES users(id),
            created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()

    # Seed admin (only if missing)
    from security import hash_password, encrypt_email, make_email_lookup
    admin_hash = make_email_lookup("admin@cyberguard.com")
    existing   = conn.execute("SELECT id FROM users WHERE email_hash=?", (admin_hash,)).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO users(name,email,email_hash,password_hash,role,is_verified) VALUES(?,?,?,?,?,?)",
            ("Admin",
             encrypt_email("admin@cyberguard.com"),
             admin_hash,
             hash_password("Admin@1234!"),
             "admin", 1)
        )
        conn.commit()
        print("  ✅ Admin seeded  →  admin@cyberguard.com  /  Admin@1234!")

    # Seed sample blog posts
    post_count = conn.execute("SELECT COUNT(*) c FROM blog_posts").fetchone()["c"]
    if post_count == 0:
        admin = conn.execute("SELECT id FROM users WHERE role='admin'").fetchone()
        if admin:
            posts = [
                ("What is Scrypt and Why It Beats bcrypt",
                 "what-is-scrypt-and-why-it-beats-bcrypt",
                 """Scrypt is a password-based key derivation function (KDF) designed to be memory-hard.

Unlike MD5 or SHA-256 (which are fast hashing algorithms), Scrypt is intentionally slow and memory-hungry — making brute-force attacks expensive.

HOW IT WORKS:
Scrypt needs ~64 MB of RAM per hash attempt. A GPU that can compute billions of SHA-256 hashes per second can only compute a few thousand Scrypt hashes per second because of the RAM bottleneck.

PARAMETERS:
  n = 2^14   → CPU/memory cost (higher = slower)
  r = 8      → block size
  p = 1      → parallelism

COMPARISON:
  MD5    → cracked in microseconds
  SHA256 → cracked in milliseconds  
  bcrypt → cracked in seconds (GPU)
  Scrypt → cracked in hours/days (GPU)

CyberGuard uses Scrypt with a unique 256-bit random salt per user — even identical passwords produce completely different hashes.""",
                 "Cryptography"),
                ("Understanding Two-Factor Authentication (2FA)",
                 "understanding-two-factor-authentication",
                 """Two-Factor Authentication (2FA) adds a second layer of security beyond passwords.

THE PROBLEM WITH PASSWORDS ALONE:
  - Users reuse passwords across sites
  - Data breaches expose millions of credentials
  - Phishing can steal passwords in real time

HOW 2FA FIXES IT:
Something you KNOW (password) + Something you HAVE (phone/email OTP)

Even if an attacker steals your password, they still need the OTP to log in. The OTP expires in 10 minutes and is single-use.

CyberGuard 2FA Flow:
  1. User enters email + password
  2. Server verifies password (Scrypt check)
  3. Server generates 6-digit OTP using secrets.randbelow()
  4. OTP emailed to user's registered address
  5. User enters OTP on /verify-otp page
  6. Server validates OTP + checks expiry
  7. Session created only if both steps pass""",
                 "Authentication"),
                ("CSRF Attacks Explained — And How We Stop Them",
                 "csrf-attacks-explained",
                 """Cross-Site Request Forgery (CSRF) tricks your browser into sending requests to a website you're already logged into.

ATTACK SCENARIO:
  1. You're logged into your bank (session cookie exists)
  2. You visit a malicious website
  3. That site has a hidden form that submits to your-bank.com/transfer
  4. Your browser automatically includes your session cookie
  5. The bank thinks YOU made the request

THE FIX — CSRF Tokens:
  1. Server generates a random token per session
  2. Token is embedded as a hidden field in every form
  3. On POST, server checks the submitted token matches the session token
  4. Malicious sites can't read your session token (same-origin policy)
  5. Request without valid token → rejected with 403

CyberGuard adds <input type="hidden" name="_csrf"> to every form automatically.""",
                 "Web Security"),
                ("SQL Injection: How It Works and How We Prevent It",
                 "sql-injection-how-it-works",
                 """SQL Injection is the #1 web attack. It exploits applications that mix user input directly into SQL queries.

VULNERABLE CODE (never do this):
  query = "SELECT * FROM users WHERE email='" + email + "'"

ATTACK — user enters this as email:
  ' OR '1'='1

RESULTING QUERY:
  SELECT * FROM users WHERE email='' OR '1'='1'
  → Returns ALL users — attacker is logged in!

WORSE ATTACK:
  '; DROP TABLE users; --
  → Deletes your entire user database!

THE FIX — Parameterised Queries:
  db.execute("SELECT * FROM users WHERE email_hash=?", (email_hash,))

The ? is a placeholder. The database driver separates SQL code from data, making injection impossible. CyberGuard uses parameterised queries everywhere — no string concatenation in any SQL statement.""",
                 "Web Security"),
            ]
            for title, slug, content, category in posts:
                conn.execute(
                    "INSERT INTO blog_posts(title,slug,content,category,author_id) VALUES(?,?,?,?,?)",
                    (title, slug, content, category, admin["id"])
                )
            conn.commit()
            print("  ✅ Sample blog posts seeded (4 articles)")

    conn.close()
