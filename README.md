# Secure Journal Blog

A private, security-hardened personal journal / blog for documenting your journey.

## Security Features

- **Authentication**: Flask-Login with strong session protection
- **Password hashing**: Bcrypt (never stores plain passwords)
- **CSRF protection**: Flask-WTF on all forms
- **Rate limiting**: Protects login/register from brute-force
- **Security headers**: CSP, X-Frame-Options, X-Content-Type-Options, etc.
- **Input sanitization**: Bleach cleans user content before storage and rendering
- **Markdown rendering**: Safe subset of tags only
- **Single-user mode**: Registration closes after the first account is created
- **Secure cookies**: HttpOnly, SameSite, Secure (HTTPS only in production)
- **SQL injection prevention**: SQLAlchemy ORM
- **Short session lifetime**: 1 hour
- **No debug mode** in production

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Create a `.env` file:
   ```
   SECRET_KEY=your-very-long-random-secret-key-here
   ```

3. Run locally:
   ```bash
   python app.py
   ```

4. Visit `http://localhost:5000`, register your account (only once), then start writing.

## Production Deployment (Recommended for Real Security)

- **Always use HTTPS** (required for Secure cookies). Use a reverse proxy like Nginx + Let's Encrypt, or deploy to Render, Railway, Fly.io, or a VPS with Caddy.
- Set a strong `SECRET_KEY` environment variable.
- Use a proper database (PostgreSQL) instead of SQLite for multi-instance setups.
- Run with Gunicorn:
  ```bash
  gunicorn -w 4 -b 0.0.0.0:5000 app:app
  ```
- Keep dependencies updated.
- Consider adding 2FA later (e.g., with pyotp).
- Regular backups of the database.
- Host behind a firewall; limit open ports.

## Why this is harder to hack

- No open registration after setup
- Brute-force protection
- No XSS via content (sanitized + CSP)
- No CSRF
- No clickjacking
- Strong password hashing
- Session fixation protection

Your journal stays private to you.

---

Built for documenting the journey: AI, career transitions, building projects, mastery, and impact.
