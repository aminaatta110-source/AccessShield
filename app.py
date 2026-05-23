"""
app.py — AccessShield Secure REST API
---------------------------------------
Security concepts in this file (read before your interview):

1. PASSWORD HASHING (bcrypt)
   Passwords are never stored in plaintext or with reversible encryption.
   bcrypt hashes them with a built-in salt and a cost factor (work factor).
   To verify a login: hash the attempt and compare — never decrypt.

2. JWT TOKENS (JSON Web Tokens)
   After login, the server issues a signed token containing the user's ID
   and an expiry time. The client sends this token in the Authorization header
   on every protected request. The server verifies the signature — no session
   storage needed (stateless auth).
   Structure: header.payload.signature (all base64-encoded)

3. RATE LIMITING
   Limits repeated requests from the same IP (e.g. 5 login attempts/minute).
   Mitigates brute-force and credential-stuffing attacks.

4. INPUT VALIDATION
   Every incoming field is validated before touching the database.
   Prevents injection attacks and unexpected application states.

5. SECURE HTTP HEADERS
   X-Content-Type-Options, X-Frame-Options, etc. prevent common browser attacks
   like MIME sniffing and clickjacking.
"""

import os
import datetime
import re

import bcrypt
import jwt
from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from database import init_db, get_db


# ── App setup ─────────────────────────────────────────────────────────────

app = Flask(__name__)

# Secret key signs JWTs — in production, load from environment variable
app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET", "dev-secret-change-in-production")
app.config["JWT_EXPIRY_HOURS"] = 2

# Rate limiter: uses client IP as the key
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
)


# ── Security headers ──────────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    """
    Attach security headers to every response.
    These headers instruct the browser to apply additional protections.
    """
    response.headers["X-Content-Type-Options"] = "nosniff"       # no MIME sniffing
    response.headers["X-Frame-Options"] = "DENY"                  # no clickjacking
    response.headers["X-XSS-Protection"] = "1; mode=block"        # XSS filter
    response.headers["Referrer-Policy"] = "strict-origin"         # limit referrer info
    response.headers["Cache-Control"] = "no-store"                # don't cache sensitive data
    return response


# ── Helpers ───────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash a password with bcrypt (includes random salt internally)."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Constant-time comparison — prevents timing attacks."""
    return bcrypt.checkpw(password.encode(), hashed.encode())


def generate_token(user_id: int) -> str:
    """
    Create a signed JWT containing user_id and expiry.
    The signature uses HMAC-SHA256 with the app's secret key.
    Tampering with the payload invalidates the signature.
    """
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(
            hours=app.config["JWT_EXPIRY_HOURS"]
        ),
        "iat": datetime.datetime.utcnow(),  # issued-at
    }
    return jwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")


def decode_token(token: str) -> dict:
    """
    Verify and decode a JWT. Raises:
    - jwt.ExpiredSignatureError if token has expired
    - jwt.InvalidTokenError if token is tampered or invalid
    """
    return jwt.decode(token, app.config["JWT_SECRET"], algorithms=["HS256"])


def require_auth(f):
    """
    Decorator for protected routes.
    Extracts Bearer token from Authorization header, verifies it,
    and injects the user_id into Flask's request context (g).
    """
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or malformed Authorization header"}), 401

        token = auth_header.split(" ", 1)[1]
        try:
            payload = decode_token(token)
            g.user_id = payload["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired — please log in again"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated


def validate_email(email: str) -> bool:
    pattern = r"^[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def validate_password_strength(password: str) -> str | None:
    """
    Return an error message if password is too weak, else None.
    Rules: 8+ chars, at least one uppercase, lowercase, digit, special char.
    """
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return "Password must contain at least one digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character"
    return None


# ── Routes ────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    """Public endpoint — confirms the API is running."""
    return jsonify({"status": "ok", "service": "AccessShield"}), 200


@app.route("/api/register", methods=["POST"])
@limiter.limit("10 per hour")  # prevent mass account creation
def register():
    """
    POST /api/register
    Body: { "username": str, "email": str, "password": str }
    Creates a new user with a hashed password.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    # Validate required fields
    for field in ("username", "email", "password"):
        if not data.get(field, "").strip():
            return jsonify({"error": f"'{field}' is required"}), 400

    username = data["username"].strip()
    email = data["email"].strip().lower()
    password = data["password"]

    # Input validation
    if len(username) < 3 or len(username) > 32:
        return jsonify({"error": "Username must be 3–32 characters"}), 400
    if not validate_email(email):
        return jsonify({"error": "Invalid email address"}), 400

    pw_error = validate_password_strength(password)
    if pw_error:
        return jsonify({"error": pw_error}), 400

    db = get_db()

    # Check for duplicate username/email
    existing = db.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
    ).fetchone()
    if existing:
        return jsonify({"error": "Username or email already registered"}), 409

    password_hash = hash_password(password)
    db.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (username, email, password_hash),
    )
    db.commit()

    return jsonify({"message": f"User '{username}' registered successfully"}), 201


@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")  # brute-force protection
def login():
    """
    POST /api/login
    Body: { "username": str, "password": str }
    Returns a signed JWT on success.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    db = get_db()
    user = db.execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()

    # Always run verify_password even if user not found — prevents timing attacks
    # that could reveal whether a username exists
    dummy_hash = "$2b$12$invalidhashfortimingprotection000000000000000000000000"
    stored_hash = user["password_hash"] if user else dummy_hash

    if not verify_password(password, stored_hash) or not user:
        return jsonify({"error": "Invalid username or password"}), 401

    token = generate_token(user["id"])
    return jsonify({"token": token, "expires_in": f"{app.config['JWT_EXPIRY_HOURS']}h"}), 200


@app.route("/api/profile", methods=["GET"])
@require_auth
def get_profile():
    """
    GET /api/profile
    Protected — requires valid JWT in Authorization: Bearer <token>
    Returns the authenticated user's profile.
    """
    db = get_db()
    user = db.execute(
        "SELECT username, email, created_at FROM users WHERE id = ?", (g.user_id,)
    ).fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "username": user["username"],
        "email": user["email"],
        "member_since": user["created_at"],
    }), 200


@app.route("/api/profile", methods=["PUT"])
@require_auth
@limiter.limit("10 per hour")
def update_profile():
    """
    PUT /api/profile
    Protected — update email or password.
    Body: { "email": str (optional), "new_password": str (optional), "current_password": str }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    db = get_db()
    user = db.execute(
        "SELECT password_hash FROM users WHERE id = ?", (g.user_id,)
    ).fetchone()

    # Require current password to make any changes
    if not verify_password(data.get("current_password", ""), user["password_hash"]):
        return jsonify({"error": "Current password incorrect"}), 403

    updates = []
    params = []

    if "email" in data:
        if not validate_email(data["email"]):
            return jsonify({"error": "Invalid email address"}), 400
        updates.append("email = ?")
        params.append(data["email"].lower())

    if "new_password" in data:
        pw_error = validate_password_strength(data["new_password"])
        if pw_error:
            return jsonify({"error": pw_error}), 400
        updates.append("password_hash = ?")
        params.append(hash_password(data["new_password"]))

    if not updates:
        return jsonify({"error": "No fields to update"}), 400

    params.append(g.user_id)
    db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
    db.commit()

    return jsonify({"message": "Profile updated successfully"}), 200


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@require_auth
def delete_account(user_id):
    """
    DELETE /api/users/<id>
    Protected — users can only delete their own account (authorisation check).
    """
    # Authorisation: ensure the requester owns this account
    if g.user_id != user_id:
        return jsonify({"error": "Forbidden — you can only delete your own account"}), 403

    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({"message": "Account deleted"}), 200


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    # debug=False in production — never expose stack traces to clients
    app.run(debug=True, port=5000)
