"""
CyberGuard v2.1 – Main Application
=====================================
NEW IN THIS VERSION:
  ✅  Email encryption  (Fernet AES-128) — emails stored as ciphertext
  ✅  Email HMAC lookup — fast search without decrypting every row
  ✅  Real OTP email    — set MAIL_USERNAME in config to send to real inboxes
  ✅  Blog with categories + rich admin editor
  ✅  Encrypted data viewer in Admin Panel
"""

import secrets, re
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, g, abort, jsonify)

import config
from models   import get_conn, init_db
from security import (hash_password, verify_password, check_password_strength,
                      generate_otp, generate_token, captcha_generate,
                      captcha_verify, sanitize, is_account_locked,
                      lockout_until, remaining_lockout,
                      encrypt_email, decrypt_email, make_email_lookup)
from mailer   import send_otp, send_verification, send_reset_link
import hmac as _hmac

# ── Flask setup ───────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key           = config.SECRET_KEY
app.permanent_session_lifetime = config.SESSION_LIFETIME
app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = "Lax",
    SESSION_COOKIE_SECURE   = False,  # True in production (HTTPS)
)

# ── DB per request ────────────────────────────────────────────────────────────
def db():
    if "db" not in g:
        g.db = get_conn()
    return g.db

@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn: conn.close()

# ── CSRF ─────────────────────────────────────────────────────────────────────
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]

def csrf_valid():
    return request.form.get("_csrf") == session.get("_csrf")

app.jinja_env.globals["csrf_token"] = csrf_token

# ── Session / user ────────────────────────────────────────────────────────────
def current_user():
    uid = session.get("user_id")
    if not uid: return None
    last = session.get("last_active")
    if last:
        if datetime.utcnow() - datetime.fromisoformat(last) > config.SESSION_LIFETIME:
            session.clear(); return None
    session["last_active"] = datetime.utcnow().isoformat()
    row = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row: return None
    # Attach decrypted email for templates
    return _user_with_email(row)

def _user_with_email(row):
    """Return user row with decrypted email attached as a dict."""
    if row is None: return None
    d = dict(row)
    d["email_plain"] = decrypt_email(d["email"])
    return d

@app.context_processor
def inject_globals():
    return dict(user=current_user(), app_name=config.APP_NAME,
                app_version=config.APP_VERSION, now=datetime.utcnow(),
                config=config)

# ── Auth decorators ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not current_user():
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        u = current_user()
        if not u or u["role"] != "admin": abort(403)
        return f(*a, **kw)
    return wrap

# ── Helpers ───────────────────────────────────────────────────────────────────
def log_login(user_id, status):
    db().execute(
        "INSERT INTO login_history(user_id,ip_address,user_agent,status) VALUES(?,?,?,?)",
        (user_id, request.remote_addr,
         request.headers.get("User-Agent","")[:250], status))
    db().commit()

def slugify(text):
    slug = re.sub(r"[^a-z0-9-]", "-", text.lower().strip()).strip("-")
    return slug + "-" + secrets.token_hex(3)

def hmac_compare(a, b):
    return _hmac.compare_digest(a.encode(), b.encode())

# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    posts = db().execute(
        "SELECT p.*,u.name author_name FROM blog_posts p "
        "JOIN users u ON p.author_id=u.id ORDER BY p.created_at DESC LIMIT 3"
    ).fetchall()
    return render_template("index.html", posts=posts)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/docs")
def docs():
    return render_template("docs.html")

@app.route("/blog")
def blog():
    category = request.args.get("cat", "")
    if category:
        posts = db().execute(
            "SELECT p.*,u.name author_name FROM blog_posts p "
            "JOIN users u ON p.author_id=u.id WHERE p.category=? ORDER BY p.created_at DESC",
            (category,)
        ).fetchall()
    else:
        posts = db().execute(
            "SELECT p.*,u.name author_name FROM blog_posts p "
            "JOIN users u ON p.author_id=u.id ORDER BY p.created_at DESC"
        ).fetchall()
    cats = db().execute(
        "SELECT DISTINCT category FROM blog_posts ORDER BY category"
    ).fetchall()
    return render_template("blog.html", posts=posts, cats=cats,
                           selected_cat=category)

@app.route("/blog/<slug>")
def blog_post(slug):
    p = db().execute(
        "SELECT p.*,u.name author_name FROM blog_posts p "
        "JOIN users u ON p.author_id=u.id WHERE p.slug=?", (slug,)
    ).fetchone()
    if not p: abort(404)
    related = db().execute(
        "SELECT p.*,u.name author_name FROM blog_posts p "
        "JOIN users u ON p.author_id=u.id "
        "WHERE p.category=? AND p.id!=? ORDER BY p.created_at DESC LIMIT 3",
        (p["category"], p["id"])
    ).fetchall()
    return render_template("post.html", post=p, related=related)

# ─────────────────────────────────────────────────────────────────────────────
#  REGISTER
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "GET" or "captcha_q" not in session:
        q, ans = captcha_generate()
        session["captcha_q"] = q; session["captcha_ans"] = ans

    if request.method == "POST":
        if not csrf_valid():
            flash("Security check failed.", "danger")
            return redirect(url_for("register"))

        name     = sanitize(request.form.get("name",""))
        email    = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        captcha  = request.form.get("captcha","")

        errors = []
        if not name or len(name) < 2:
            errors.append("Name must be at least 2 characters.")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            errors.append("Invalid email address.")
        if check_password_strength(password)["score"] < 3:
            errors.append("Password too weak. Use uppercase, number, and special character.")
        if not captcha_verify(captcha, session.get("captcha_ans")):
            errors.append("Incorrect CAPTCHA answer.")

        if errors:
            for e in errors: flash(e, "danger")
            q, ans = captcha_generate()
            session["captcha_q"] = q; session["captcha_ans"] = ans
            return render_template("register.html", captcha_q=session["captcha_q"])

        # Check duplicate via email_hash (not raw email)
        eh = make_email_lookup(email)
        if db().execute("SELECT id FROM users WHERE email_hash=?", (eh,)).fetchone():
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))

        # Store ENCRYPTED email + HMAC hash + Scrypt password
        enc_email = encrypt_email(email)
        ph        = hash_password(password)
        db().execute(
            "INSERT INTO users(name,email,email_hash,password_hash) VALUES(?,?,?,?)",
            (sanitize(name), enc_email, eh, ph)
        )
        db().commit()
        user = db().execute("SELECT * FROM users WHERE email_hash=?", (eh,)).fetchone()

        # Send verification email
        token   = generate_token()
        expires = (datetime.utcnow() + timedelta(hours=24)).isoformat()
        db().execute(
            "INSERT INTO email_tokens(user_id,token,purpose,expires_at) VALUES(?,?,?,?)",
            (user["id"], token, "verify", expires))
        db().commit()
        link = url_for("verify_email", token=token, _external=True)
        send_verification(email, name, link)

        flash("Account created! Check your email (or terminal) for the verification link.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", captcha_q=session.get("captcha_q",""))


@app.route("/verify-email/<token>")
def verify_email(token):
    row = db().execute(
        "SELECT * FROM email_tokens WHERE token=? AND purpose='verify' AND used=0",
        (token,)).fetchone()
    if not row:
        flash("Invalid or expired verification link.", "danger")
        return redirect(url_for("login"))
    if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
        flash("Link expired. Please register again.", "danger")
        return redirect(url_for("register"))
    db().execute("UPDATE users SET is_verified=1 WHERE id=?", (row["user_id"],))
    db().execute("UPDATE email_tokens SET used=1 WHERE id=?", (row["id"],))
    db().commit()
    flash("Email verified! You can now log in.", "success")
    return redirect(url_for("login"))

# ─────────────────────────────────────────────────────────────────────────────
#  LOGIN
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET","POST"])
def login():
    if current_user(): return redirect(url_for("dashboard"))
    if request.method == "GET" or "login_captcha_q" not in session:
        q, ans = captcha_generate()
        session["login_captcha_q"] = q; session["login_captcha_ans"] = ans

    if request.method == "POST":
        if not csrf_valid():
            flash("Security check failed.", "danger")
            return redirect(url_for("login"))

        email    = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        captcha  = request.form.get("captcha","")

        if not captcha_verify(captcha, session.get("login_captcha_ans")):
            flash("Incorrect CAPTCHA. Please try again.", "danger")
            return _refresh_login_captcha()

        # Lookup by email_hash (never by raw email)
        eh   = make_email_lookup(email)
        user = db().execute("SELECT * FROM users WHERE email_hash=?", (eh,)).fetchone()

        GENERIC = "Invalid email or password."
        if not user:
            flash(GENERIC, "danger")
            return _refresh_login_captcha()

        if user["is_blocked"]:
            flash("Your account has been blocked by an administrator.", "danger")
            log_login(user["id"], "blocked")
            return _refresh_login_captcha()

        if is_account_locked(user["locked_until"]):
            secs = remaining_lockout(user["locked_until"])
            flash(f"⛔ Account locked. Try again in {max(1,secs//60)} minute(s).", "danger")
            log_login(user["id"], "blocked")
            return _refresh_login_captcha()

        if not verify_password(password, user["password_hash"]):
            attempts = user["login_attempts"] + 1
            if attempts >= config.MAX_LOGIN_ATTEMPTS:
                db().execute(
                    "UPDATE users SET login_attempts=?,locked_until=? WHERE id=?",
                    (attempts, lockout_until(), user["id"]))
                db().commit()
                log_login(user["id"], "failed")
                flash(f"⛔ Too many failed attempts. Account locked for {config.LOCKOUT_MINUTES} minutes.", "danger")
            else:
                db().execute("UPDATE users SET login_attempts=? WHERE id=?", (attempts, user["id"]))
                db().commit()
                log_login(user["id"], "failed")
                flash(f"{GENERIC} {config.MAX_LOGIN_ATTEMPTS - attempts} attempt(s) remaining.", "danger")
            return _refresh_login_captcha()

        if not user["is_verified"]:
            flash("Please verify your email before logging in.", "warning")
            return _refresh_login_captcha()

        # Reset attempts on success
        db().execute("UPDATE users SET login_attempts=0,locked_until=NULL WHERE id=?", (user["id"],))
        db().commit()

        # Generate and send OTP (to REAL email — decrypted from DB)
        otp, expires = generate_otp()
        db().execute(
            "INSERT INTO otp_tokens(user_id,token,purpose,expires_at) VALUES(?,?,?,?)",
            (user["id"], otp, "login", expires.isoformat()))
        db().commit()

        real_email = decrypt_email(user["email"])
        send_otp(real_email, user["name"], otp, purpose="login")

        session["pending_2fa_uid"] = user["id"]
        flash("OTP sent! Check your email inbox (or terminal in dev mode).", "info")
        return redirect(url_for("verify_otp"))

    return render_template("login.html", captcha_q=session.get("login_captcha_q",""))


def _refresh_login_captcha():
    q, ans = captcha_generate()
    session["login_captcha_q"] = q; session["login_captcha_ans"] = ans
    return render_template("login.html", captcha_q=session["login_captcha_q"])

# ─────────────────────────────────────────────────────────────────────────────
#  OTP VERIFY
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/verify-otp", methods=["GET","POST"])
def verify_otp():
    uid = session.get("pending_2fa_uid")
    if not uid: return redirect(url_for("login"))

    if request.method == "POST":
        if not csrf_valid():
            flash("Security check failed.", "danger")
            return redirect(url_for("verify_otp"))

        entered = request.form.get("otp","").strip()
        row = db().execute(
            "SELECT * FROM otp_tokens WHERE user_id=? AND purpose='login' "
            "AND used=0 ORDER BY id DESC LIMIT 1", (uid,)).fetchone()

        if not row:
            flash("No OTP found. Please log in again.", "danger")
            return redirect(url_for("login"))
        if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            flash("OTP expired. Please log in again.", "danger")
            return redirect(url_for("login"))
        if not hmac_compare(entered, row["token"]):
            flash("Incorrect OTP. Please try again.", "danger")
            return render_template("verify_otp.html")

        db().execute("UPDATE otp_tokens SET used=1 WHERE id=?", (row["id"],))
        db().commit()
        session.pop("pending_2fa_uid", None)
        session["user_id"] = uid
        session["last_active"] = datetime.utcnow().isoformat()
        session.permanent = True

        log_login(uid, "success")
        user = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        flash(f"Welcome back, {user['name']}! 🔐", "success")
        return redirect(url_for("dashboard"))

    return render_template("verify_otp.html")

# ─────────────────────────────────────────────────────────────────────────────
#  FORGOT / RESET PASSWORD
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/forgot-password", methods=["GET","POST"])
def forgot_password():
    if request.method == "POST":
        if not csrf_valid():
            flash("Security check failed.", "danger")
            return redirect(url_for("forgot_password"))
        email = request.form.get("email","").strip().lower()
        eh    = make_email_lookup(email)
        user  = db().execute("SELECT * FROM users WHERE email_hash=?", (eh,)).fetchone()
        flash("If that email exists, a reset link has been sent.", "info")
        if user:
            token   = generate_token()
            expires = (datetime.utcnow() + timedelta(minutes=30)).isoformat()
            db().execute(
                "INSERT INTO email_tokens(user_id,token,purpose,expires_at) VALUES(?,?,?,?)",
                (user["id"], token, "reset", expires))
            db().commit()
            link = url_for("reset_password", token=token, _external=True)
            real_email = decrypt_email(user["email"])
            send_reset_link(real_email, user["name"], link)
        return redirect(url_for("forgot_password"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET","POST"])
def reset_password(token):
    row = db().execute(
        "SELECT * FROM email_tokens WHERE token=? AND purpose='reset' AND used=0",
        (token,)).fetchone()
    if not row or datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        if not csrf_valid():
            flash("Security check failed.", "danger")
            return redirect(request.url)
        password = request.form.get("password","")
        confirm  = request.form.get("confirm","")
        if check_password_strength(password)["score"] < 3:
            flash("Password too weak.", "danger")
            return render_template("reset_password.html", token=token)
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)
        db().execute(
            "UPDATE users SET password_hash=?,login_attempts=0,locked_until=NULL WHERE id=?",
            (hash_password(password), row["user_id"]))
        db().execute("UPDATE email_tokens SET used=1 WHERE id=?", (row["id"],))
        db().commit()
        flash("Password reset successfully. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)

# ─────────────────────────────────────────────────────────────────────────────
#  LOGOUT
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out securely.", "info")
    return redirect(url_for("home"))

# ─────────────────────────────────────────────────────────────────────────────
#  PROTECTED PAGES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    history = db().execute(
        "SELECT * FROM login_history WHERE user_id=? ORDER BY login_time DESC LIMIT 10",
        (u["id"],)).fetchall()
    return render_template("dashboard.html", history=history)


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@app.route("/security")
@login_required
def security():
    u = current_user()
    history = db().execute(
        "SELECT * FROM login_history WHERE user_id=? ORDER BY login_time DESC LIMIT 20",
        (u["id"],)).fetchall()
    score = 0; alerts = []
    if u["is_verified"]:  score += 25
    else: alerts.append({"level":"danger","msg":"Email not verified"})
    if u["password_hash"] and "$" in u["password_hash"]: score += 25
    failed = sum(1 for h in history if h["status"]=="failed")
    if failed == 0: score += 25
    elif failed < 3: score += 10; alerts.append({"level":"warning","msg":f"{failed} recent failed login(s)"})
    else: alerts.append({"level":"danger","msg":f"{failed} failed logins — possible attack"})
    if u["login_attempts"] == 0: score += 25
    score_label = "Excellent" if score>=90 else "Good" if score>=60 else "At Risk"
    score_css   = "success"   if score>=90 else "warning" if score>=60 else "danger"
    return render_template("security.html", history=history, score=score,
                           score_label=score_label, score_css=score_css, alerts=alerts)

# ─────────────────────────────────────────────────────────────────────────────
#  ADMIN
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/admin")
@login_required
@admin_required
def admin():
    # Decrypt emails for display
    raw_users = db().execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    users = []
    for u in raw_users:
        d = dict(u)
        d["email_plain"] = decrypt_email(d["email"])
        users.append(d)

    posts = db().execute(
        "SELECT p.*,u.name author_name FROM blog_posts p "
        "JOIN users u ON p.author_id=u.id ORDER BY p.created_at DESC"
    ).fetchall()
    history = db().execute(
        "SELECT h.*,u.name uname FROM login_history h "
        "JOIN users u ON h.user_id=u.id ORDER BY h.login_time DESC LIMIT 50"
    ).fetchall()
    stats = {
        "total":        len(users),
        "active":       sum(1 for u in users if not u["is_blocked"] and u["is_verified"]),
        "blocked":      sum(1 for u in users if u["is_blocked"]),
        "unverified":   sum(1 for u in users if not u["is_verified"]),
        "failed_today": db().execute(
            "SELECT COUNT(*) c FROM login_history WHERE status='failed' "
            "AND date(login_time)=date('now')"
        ).fetchone()["c"],
    }

    # Encrypted data samples for the visual panel in admin.html
    # Each sample shows: name, decrypted email, truncated ciphertext, hmac preview, pw preview
    enc_samples = []
    for u in users[:5]:
        enc_samples.append({
            "name":         u["name"],
            "email_plain":  u["email_plain"],
            "email_cipher": u["email"][:48] + "…" if len(u["email"]) > 48 else u["email"],
            "email_hmac":   u["email_hash"][:20] if u.get("email_hash") else "hmac…",
            "pw_preview":   u["password_hash"][:24] if u.get("password_hash") else "hash…",
        })

    cats = db().execute("SELECT DISTINCT category FROM blog_posts ORDER BY category").fetchall()
    return render_template("admin.html", users=users, posts=posts, history=history,
                           stats=stats, enc_samples=enc_samples, cats=cats)


@app.route("/admin/block/<int:uid>", methods=["POST"])
@login_required
@admin_required
def admin_block(uid):
    if not csrf_valid(): abort(403)
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if u and u["role"] != "admin":
        new_val = 0 if u["is_blocked"] else 1
        db().execute("UPDATE users SET is_blocked=? WHERE id=?", (new_val, uid))
        db().commit()
        flash(f"User {u['name']} {'unblocked' if new_val==0 else 'blocked'}.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/delete/<int:uid>", methods=["POST"])
@login_required
@admin_required
def admin_delete(uid):
    if not csrf_valid(): abort(403)
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if u and u["role"] != "admin":
        db().execute("DELETE FROM users WHERE id=?", (uid,))
        db().commit()
        flash(f"User {u['name']} deleted.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/post", methods=["POST"])
@login_required
@admin_required
def admin_post():
    if not csrf_valid(): abort(403)
    title    = sanitize(request.form.get("title",""))
    content  = request.form.get("content","")
    category = sanitize(request.form.get("category","General"))
    if title and content:
        slug = slugify(title)
        db().execute(
            "INSERT INTO blog_posts(title,slug,content,category,author_id) VALUES(?,?,?,?,?)",
            (title, slug, content, category, current_user()["id"]))
        db().commit()
        flash("Post published.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/delete-post/<int:pid>", methods=["POST"])
@login_required
@admin_required
def admin_delete_post(pid):
    if not csrf_valid(): abort(403)
    db().execute("DELETE FROM blog_posts WHERE id=?", (pid,))
    db().commit()
    flash("Post deleted.", "success")
    return redirect(url_for("admin"))

# ─────────────────────────────────────────────────────────────────────────────
#  API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/password-strength", methods=["POST"])
def api_pw_strength():
    pw = request.json.get("password","") if request.is_json else ""
    return jsonify(check_password_strength(pw))

# ─────────────────────────────────────────────────────────────────────────────
#  ERRORS
# ─────────────────────────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(_): return render_template("error.html",code=403,msg="Access denied."),403

@app.errorhandler(404)
def not_found(_): return render_template("error.html",code=404,msg="Page not found."),404

@app.errorhandler(500)
def server_error(_): return render_template("error.html",code=500,msg="Internal server error."),500

# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*62)
    print(f"  🛡  CyberGuard v{config.APP_VERSION}")
    print("="*62)
    init_db()
    email_mode = "📧 Real email (SMTP)" if config.MAIL_USERNAME else "💻 Dev mode (print to terminal)"
    print(f"\n  🌐  http://127.0.0.1:5000")
    print(f"  🔑  admin@cyberguard.com  /  Admin@1234!")
    print(f"  📬  OTP delivery: {email_mode}")
    print(f"  🔒  Email encryption: Fernet AES-128 (active)")
    print("="*62 + "\n")
    app.run(debug=True, port=5000)
