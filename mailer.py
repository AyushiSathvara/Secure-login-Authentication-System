"""
CyberGuard – Email Utility v2.1
=================================
Sends OTPs, verification links, and password reset links.
- If MAIL_USERNAME is set → sends real email via Gmail SMTP
- If blank → prints to terminal (dev mode) with clear formatting
"""

import smtplib, ssl, re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM, APP_NAME


def _strip_tags(html_body: str) -> str:
    return re.sub(r"<[^>]+>", "", html_body).strip()


def _send(to: str, subject: str, html_body: str):
    """Core send. Falls back to pretty terminal output in dev mode."""
    if not MAIL_USERNAME:
        # ── DEV MODE: print to terminal ──────────────────────────────────────
        border = "─" * 58
        print(f"\n┌{border}┐")
        print(f"│  📧  DEV EMAIL — would be sent to real inbox in prod")
        print(f"│  To      : {to}")
        print(f"│  Subject : [{APP_NAME}] {subject}")
        print(f"│{border}│")
        text = _strip_tags(html_body)
        for line in text.split("\n"):
            line = line.strip()
            if line:
                print(f"│  {line}")
        print(f"└{border}┘\n")
        return

    # ── PRODUCTION: real SMTP send ────────────────────────────────────────────
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[{APP_NAME}] {subject}"
    msg["From"]    = MAIL_FROM
    msg["To"]      = to
    msg.attach(MIMEText(html_body, "html"))

    context = ssl.create_default_context()
    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
        server.ehlo()
        server.starttls(context=context)
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_FROM, to, msg.as_string())
    print(f"  ✅ Email sent → {to}")


def _wrap(title: str, body: str) -> str:
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;
                background:#0f172a;color:#e2e8f0;padding:32px;border-radius:12px;
                border:1px solid #1e293b;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
        <span style="font-size:22px;">🛡</span>
        <span style="font-weight:900;font-size:16px;letter-spacing:2px;color:#6366f1;">CYBERGUARD</span>
      </div>
      <div style="height:1px;background:#1e293b;margin:16px 0 24px;"></div>
      <h2 style="color:#f1f5f9;font-size:18px;margin:0 0 16px;">{title}</h2>
      {body}
      <div style="height:1px;background:#1e293b;margin:24px 0 16px;"></div>
      <p style="font-size:11px;color:#475569;margin:0;">
        This is an automated security message. Do not reply.<br/>
        If you did not request this, you can safely ignore this email.
      </p>
    </div>"""


def send_otp(to: str, name: str, otp: str, purpose: str = "login"):
    action = "Two-Factor Login Verification" if purpose == "login" else "Password Reset OTP"
    body = _wrap(action, f"""
        <p style="color:#94a3b8;margin:0 0 12px;">Hi <strong style="color:#e2e8f0">{name}</strong>,</p>
        <p style="color:#94a3b8;margin:0 0 20px;">Your one-time password (OTP) is:</p>
        <div style="background:#0f0f23;border:1px solid #6366f1;border-radius:10px;
                    padding:20px;text-align:center;margin:0 0 20px;">
          <span style="font-size:42px;font-weight:900;letter-spacing:14px;
                       color:#6366f1;font-family:monospace;">{otp}</span>
        </div>
        <p style="color:#94a3b8;margin:0;">
          ⏱ Expires in <strong style="color:#f59e0b">10 minutes</strong>.<br/>
          🔒 Never share this code with anyone — CyberGuard will never ask for it.
        </p>""")
    _send(to, action, body)


def send_verification(to: str, name: str, link: str):
    body = _wrap("Verify Your Email Address", f"""
        <p style="color:#94a3b8;margin:0 0 12px;">Hi <strong style="color:#e2e8f0">{name}</strong>,</p>
        <p style="color:#94a3b8;margin:0 0 24px;">
          Click the button below to activate your CyberGuard account.
        </p>
        <div style="text-align:center;margin:0 0 24px;">
          <a href="{link}" style="background:#6366f1;color:#fff;padding:13px 32px;
             border-radius:8px;text-decoration:none;font-weight:700;font-size:14px;
             display:inline-block;">✅ Verify My Email</a>
        </div>
        <p style="font-size:12px;color:#475569;word-break:break-all;">
          Or copy this link: {link}
        </p>
        <p style="color:#94a3b8;margin:12px 0 0;">
          ⏱ Link expires in <strong style="color:#f59e0b">24 hours</strong>.
        </p>""")
    _send(to, "Verify Your Email Address", body)


def send_reset_link(to: str, name: str, link: str):
    body = _wrap("Password Reset Request", f"""
        <p style="color:#94a3b8;margin:0 0 12px;">Hi <strong style="color:#e2e8f0">{name}</strong>,</p>
        <p style="color:#94a3b8;margin:0 0 24px;">
          Someone requested a password reset for your account. If this was you, click below:
        </p>
        <div style="text-align:center;margin:0 0 24px;">
          <a href="{link}" style="background:#ef4444;color:#fff;padding:13px 32px;
             border-radius:8px;text-decoration:none;font-weight:700;font-size:14px;
             display:inline-block;">🔑 Reset My Password</a>
        </div>
        <p style="font-size:12px;color:#475569;word-break:break-all;">{link}</p>
        <p style="color:#94a3b8;margin:12px 0 0;">
          ⏱ Expires in <strong style="color:#f59e0b">30 minutes</strong>.<br/>
          If you did not request this, your password is safe — ignore this email.
        </p>""")
    _send(to, "Password Reset Request", body)
