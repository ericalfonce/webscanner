"""
make_admin.py — Grant or revoke admin role for any user account.

Usage (from project root, with venv activated):
    python make_admin.py your@email.com
    python make_admin.py your@email.com --role pro
    python make_admin.py your@email.com --role free
"""

import sys
from app import create_app
from models import db, User

VALID_ROLES = ("free", "basic", "pro", "enterprise", "admin")


def main():
    if len(sys.argv) < 2:
        print("Usage: python make_admin.py <email> [--role <role>]")
        print(f"Roles: {', '.join(VALID_ROLES)}")
        sys.exit(1)

    email = sys.argv[1].strip().lower()

    # Parse optional --role flag
    role = "admin"
    if "--role" in sys.argv:
        idx = sys.argv.index("--role")
        if idx + 1 < len(sys.argv):
            role = sys.argv[idx + 1].strip().lower()

    if role not in VALID_ROLES:
        print(f"Invalid role '{role}'. Choose from: {', '.join(VALID_ROLES)}")
        sys.exit(1)

    app = create_app()
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"No user found with email: {email}")
            print("Make sure you register first, then run this script.")
            sys.exit(1)

        old_role = user.role
        user.role = role

        # Admin gets unlimited scans
        if role == "admin":
            user.monthly_scan_limit = 9999
            user.email_verified = True   # skip email gate for admin

        db.session.commit()
        print(f"Done.  {email}  {old_role} → {role}")


if __name__ == "__main__":
    main()
