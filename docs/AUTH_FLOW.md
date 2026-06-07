# Authentication Flow

The application uses **email/password** authentication for the desktop UI and API interactions.

## Registration
- Endpoint: **POST /api/auth/register**
- Payload: `{ "username": "...", "email": "...", "password": "...", "password_confirm": "..." }`
- The server validates username, email, and password strength.
- Passwords are hashed using **bcrypt** (`bcrypt.hashpw(...).decode('utf-8')`).
- The user record is saved to the database without the password hash being returned.

## Login
- Endpoint: **POST /api/auth/login**
- Payload: `{ "username": "...", "password": "..." }` (or email as identifier)
- The server verifies the password with `bcrypt.checkpw`.
- On success a **JWT** token is issued.
- **Token Delivery**: The token is delivered via an `HttpOnly` cookie AND returned in the JSON response to be used in the `Authorization: Bearer <token>` header.

## Profile & Session Management
- **Get Profile**: **GET /api/auth/profile**
  - Returns current user details and role. Requires authentication.
- **Change Password**: **POST /api/auth/change-password**
  - Payload: `{ "current_password": "...", "new_password": "..." }`
- **Logout**: **POST /api/auth/logout**
  - Invalidates the current session and clears the `HttpOnly` cookie.

## Token Validation & Expiry
- All protected API routes require the `Authorization: Bearer <token>` header OR the `pp_auth_token` cookie.
- Tokens expire based on the `AUTH_TOKEN_EXPIRY` setting (configurable, default `1800s` or 30 minutes).
- `AuthService.verify_token` validates signature, expiry, and device fingerprint.

## Device Fingerprinting
- During login, the server captures a device fingerprint (User-Agent, IP address).
- This fingerprint is embedded in the JWT.
- Subsequent requests must match the fingerprint, preventing token theft and replay attacks from different devices.

## Role-Based Access Control (RBAC)
- Users are assigned roles: `admin`, `operator`, or `viewer`.
- Roles determine access to sensitive endpoints (e.g., only admins can change global settings or manage other users).

## Rate Limiting
- Global rate limit: `RATE_LIMIT_MAX_REQUESTS` (default 100) per `RATE_LIMIT_WINDOW_SECONDS` (default 60s).
- Separate limits for login: `RATE_LIMIT_LOGIN_ATTEMPTS` (default 5 attempts).
- Registration limit: `RATE_LIMIT_LOGIN_ATTEMPTS * 2` (default 10 attempts).

## Password Policies
- Minimum **12** characters.
- Must include upper‑case, lower‑case, digits, and special characters.
- Enforced consistently by both `AuthService` and `UserService`.

---
*All security‑relevant settings are defined in `backend/config/config.py`.*