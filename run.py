"""
CyberGuard – Quick Start
Run this file instead of app.py for a cleaner startup experience.
Usage: python run.py
"""
from models import init_db
from app import app
import config

if __name__ == "__main__":
    print("\n" + "="*60)
    print(f"  🛡  CyberGuard v{config.APP_VERSION} – Starting")
    print("="*60)
    print("  Initialising database...")
    init_db()
    email_mode = "📧 Real email (SMTP)" if config.MAIL_USERNAME else "💻 Dev mode (OTP prints here)"
    print(f"  OTP delivery : {email_mode}")
    print(f"  Encryption   : Fernet AES-128 (active)")
    print(f"\n  🌐  Open: http://127.0.0.1:5000")
    print(f"  👤  Admin: admin@cyberguard.com  /  Admin@1234!")
    print("="*60 + "\n")
    app.run(debug=True, port=5000)
