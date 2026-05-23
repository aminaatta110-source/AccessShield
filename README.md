# AccessShield 🛡️

A secure RESTful API with token-based authentication and authorization, built with Flask. Demonstrates real-world secure API design patterns.

## Security features

| Feature | Implementation | Protects Against |
|---|---|---|
| Password hashing | bcrypt (cost factor 12) | Database breaches |
| Stateless auth | JWT (HS256, 2h expiry) | Session hijacking |
| Rate limiting | 5 login attempts/min | Brute-force attacks |
| Input validation | Regex + length checks | Injection, bad data |
| Timing-safe comparison | bcrypt.checkpw | Timing attacks |
| Security headers | X-Frame-Options, etc. | XSS, clickjacking |
| Authorization checks | Owner-only deletion | Privilege escalation |

## Endpoints

| Method | Route | Auth | Description |
|---|---|---|---|
| GET | `/api/health` | Public | Health check |
| POST | `/api/register` | Public | Create account |
| POST | `/api/login` | Public | Get JWT token |
| GET | `/api/profile` | 🔒 Bearer token | View profile |
| PUT | `/api/profile` | 🔒 Bearer token | Update profile |
| DELETE | `/api/users/:id` | 🔒 Bearer token | Delete account |

## Setup

```bash
pip install -r requirements.txt
python app.py
```

## Example usage

```bash
# Register
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"amina","email":"amina@email.com","password":"Secure@123"}'

# Login → get token
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"amina","password":"Secure@123"}'

# Access protected route
curl http://localhost:5000/api/profile \
  -H "Authorization: Bearer <token>"
```

## Tech stack

- Python 3.10+
- [Flask](https://flask.palletsprojects.com/) — REST framework
- [bcrypt](https://github.com/pyca/bcrypt/) — password hashing
- [PyJWT](https://pyjwt.readthedocs.io/) — JSON Web Tokens
- [Flask-Limiter](https://flask-limiter.readthedocs.io/) — rate limiting
- SQLite (swap for PostgreSQL in production)
