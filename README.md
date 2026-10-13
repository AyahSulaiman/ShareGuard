# ShareGuard
Secure file sharing: invite only expiring links, download limits, 2FA, and audit logs.
Status: Work in progress. Implemented so far: user signup with Argon2 password hashing, JWT login with protected routes, file upload with a size limit, and invite-only share links with expiry, download limits and revocation (FastAPI + SQLModel).