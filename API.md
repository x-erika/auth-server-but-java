# auth-server-but-java — API Reference

Base URL: `http://localhost:8080` (default; override via `auth.issuer.url`)

## Prerequisites

Set these env vars in your shell before `./mvnw quarkus:dev`:

```bash
# bash / zsh / git-bash
export DB_URL=jdbc:postgresql://localhost:5432/auth_xerika
export DB_USER=postgres
export DB_PASS=postgres
```

```powershell
# PowerShell
$env:DB_URL = "jdbc:postgresql://localhost:5432/auth_xerika"
$env:DB_USER = "postgres"
$env:DB_PASS = "postgres"
```

Postgres must be running and have a database matching `DB_URL`. Flyway will run V1–V4 migrations on startup.

The repo also defaults to local dev values (`localhost:15552`, user `postgres`, pass `erika`, db `xerika-java`) if env vars are not set — see `application.properties`.

On first start, an RSA keypair is generated at `~/.xerika/auth/keys/` and an admin user is bootstrapped: `admin@gmail.com` / `admin123` (assigned `admin` role).

## Token types

| Token | Source | Use |
|---|---|---|
| **Session token** (opaque) | `POST /auth/login` or `POST /login` (HTML) | `/auth/me`, `/auth/logout`, `/oauth/authorize`, `/admin/*`, `/oauth/logout`, `/oauth/device/verify` |
| **Access token** (JWT, RS256) | `POST /oauth/token` | `/userinfo` and any endpoint guarded by `@RequiresScope` |
| **Refresh token** (opaque, sha256-hashed in DB) | `POST /oauth/token` | Used at `/oauth/token` with `grant_type=refresh_token` |
| **ID token** (JWT, RS256) | `POST /oauth/token` if scope includes `openid` | Identity assertion for OIDC clients |

Session tokens accepted in: `Authorization: Bearer <token>` header, `X-Session-Token: <token>` header, or `session_token` cookie (set by HTML login at `POST /login`). Header wins if both present.

Access tokens (JWT) are sent only via `Authorization: Bearer <token>`.

---

## Auth (session-based)

### `POST /auth/signup`

Public. Creates an unverified user with `user` role assigned.

Request:
```json
{
  "email": "alice@example.com",
  "password": "minimum8chars",
  "username": "alice",
  "firstName": "Alice",
  "lastName": "Smith"
}
```

Response `201 Created`:
```json
{
  "message": "signup successful, verify your email",
  "userId": "<uuid>",
  "verificationToken": "<base64url-token>"
}
```

> The `verificationToken` is returned in the response for dev/testing. In prod, this would be emailed — the response would only contain `message` and `userId`.

Errors:
- `400` invalid_request — missing fields or password < 8 chars
- `409` conflict — email or username already taken

```bash
curl -X POST http://localhost:8080/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"password123","username":"alice"}'
```

---

### `POST /auth/verify-email`

Public. Marks user as `emailVerified=true` and consumes the token.

Request:
```json
{ "token": "<verificationToken from signup>" }
```

Response `200`:
```json
{ "message": "email verified", "userId": "<uuid>" }
```

Errors:
- `400` invalid_token — token not found / expired / already used

```bash
curl -X POST http://localhost:8080/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{"token":"<paste-token-here>"}'
```

---

### `POST /auth/login`

Public. Authenticates by email + password (user must have `emailVerified=true`). Creates a session that lasts 8 hours.

Request:
```json
{ "email": "admin@gmail.com", "password": "admin123" }
```

Response `200`:
```json
{
  "message": "login success",
  "session": {
    "sessionToken": "<opaque>",
    "expiresAt": "2026-05-12T04:30:00",
    "lastAccessedAt": "2026-05-11T20:30:00"
  },
  "user": {
    "id": "<uuid>",
    "email": "admin@gmail.com",
    "username": "admin",
    "emailVerified": true,
    "roles": ["admin"]
  }
}
```

Errors: `401` invalid credentials (also returned for non-existent users, disabled users, unverified emails — to prevent enumeration)

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@gmail.com","password":"admin123"}'
```

---

### `GET /login` / `POST /login` (HTML)

Browser-facing login. `GET` renders an HTML form. `POST` (form-encoded) authenticates, creates a session, sets `session_token` cookie (HttpOnly, SameSite=Lax, 8h), and 302-redirects to `return_to` (if a safe relative path) or `/`.

Used in the OAuth flow: when `GET /oauth/authorize` is hit without a valid session, the server auto-redirects to `/login?return_to=<original-url>`. After login, the user is sent back to complete the authorization.

`return_to` is restricted to relative paths starting with `/` (no open redirect).

```bash
# Render form
curl http://localhost:8080/login

# Submit (browser does this)
curl -i -X POST http://localhost:8080/login \
  -d "email=admin@gmail.com" \
  -d "password=admin123" \
  -d "return_to=/oauth/authorize?response_type=code&client_id=web-app&..."
# → 303 See Other with Set-Cookie: session_token=...; HttpOnly
```

---

### `GET /auth/me`

Requires session token.

Response `200`:
```json
{
  "session": { "sessionToken": "...", "expiresAt": "...", "lastAccessedAt": "..." },
  "user": { "id": "...", "email": "...", "username": "...", "emailVerified": true, "roles": ["admin"] }
}
```

Errors: `401` invalid session (expired / unknown / user disabled)

```bash
curl http://localhost:8080/auth/me \
  -H "Authorization: Bearer <sessionToken>"
```

---

### `POST /auth/logout`

Requires session token. Deletes the session.

Response `200`:
```json
{ "message": "logout success" }
```

```bash
curl -X POST http://localhost:8080/auth/logout \
  -H "Authorization: Bearer <sessionToken>"
```

---

## OAuth 2.0 + OIDC

### `GET /oauth/authorize`

Requires session token (the user must be logged in). Authorization Code grant only.

Query parameters:

| Param | Required | Notes |
|---|---|---|
| `client_id` | yes | Bootstrap client: `web-app` |
| `redirect_uri` | yes | Must be registered. Bootstrap: `http://localhost:3000/callback` |
| `response_type` | yes | Only `code` is supported |
| `scope` | optional | Space-separated. Bootstrap allows: `openid`, `profile`, `email` |
| `state` | optional but recommended | Echoed back in redirect |
| `nonce` | optional but recommended for OIDC | Carried into id_token |
| `code_challenge` | required if client has `pkceRequired=true` | PKCE challenge |
| `code_challenge_method` | optional | `S256` (recommended) or `plain`. Default `plain` |
| `prompt` | optional | `none` returns `login_required` error if no session; `login` forces re-auth |
| `max_age` | optional | Seconds. If session.createdAt is older, treated as needing re-auth |

Success: `303 See Other` redirect to `redirect_uri?code=<code>&state=<state>`

Errors (returned as `400 JSON`, not redirect):
- `unsupported_response_type`
- `invalid_request` (missing params, bad pkce method)
- `invalid_session`
- `login_required` (with `prompt=none` and no session)
- `unauthorized_client`
- `invalid_scope`

```bash
# Generate PKCE pair first (S256):
#   verifier = random 43-char url-safe string
#   challenge = base64url(sha256(verifier))
#
# In bash:
#   verifier=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
#   challenge=$(echo -n "$verifier" | openssl dgst -sha256 -binary | openssl base64 | tr -d "=+/")

curl -i "http://localhost:8080/oauth/authorize?\
response_type=code&\
client_id=web-app&\
redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&\
scope=openid+profile+email&\
state=xyz123&\
nonce=abc456&\
code_challenge=$challenge&\
code_challenge_method=S256" \
  -H "Authorization: Bearer <sessionToken>"
# Look for "Location:" header → contains code=...
```

---

### `POST /oauth/token`

Public (client_id required; secret only for confidential clients). Form-encoded.

Two grant types supported: `authorization_code` and `refresh_token`.

#### Authorization Code grant

Body (form-urlencoded):
```
grant_type=authorization_code
code=<code from /authorize>
redirect_uri=<must match the authorize request>
client_id=web-app
code_verifier=<PKCE verifier — required if client has pkceRequired>
client_secret=<only if client.type is confidential>
```

Response `200`:
```json
{
  "token_type": "Bearer",
  "expires_in": 900,
  "access_token": "<JWT RS256>",
  "refresh_token": "<opaque>",
  "scope": "openid profile email",
  "id_token": "<JWT RS256, only if scope contains openid>"
}
```

Access token claims (decode JWT to inspect):
```json
{
  "iss": "http://localhost:8080",
  "sub": "<user-uuid>",
  "aud": "web-app",
  "exp": 1734567890,
  "iat": 1734566990,
  "jti": "<uuid>",
  "email": "admin@gmail.com",
  "username": "admin",
  "sid": "<session-uuid>",
  "roles": ["admin"],
  "scope": "openid profile email"
}
```

ID token claims (only emitted with `openid` scope):
```json
{
  "iss": "http://localhost:8080",
  "sub": "<user-uuid>",
  "aud": "web-app",
  "exp": 1734570590,
  "iat": 1734566990,
  "jti": "<uuid>",
  "auth_time": 1734566500,
  "nonce": "<echoed from authorize>",
  "email": "admin@gmail.com",
  "email_verified": true,
  "preferred_username": "admin",
  "given_name": "Admin",
  "family_name": "User",
  "name": "Admin User"
}
```

Errors `400`:
- `invalid_request` — missing fields
- `unauthorized_client`
- `invalid_client` — bad secret for confidential client
- `invalid_grant` — bad code / expired / PKCE mismatch / redirect_uri mismatch

```bash
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=<paste-code>" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=web-app" \
  -d "code_verifier=<paste-verifier>"
```

#### Refresh Token grant

```
grant_type=refresh_token
refresh_token=<from previous token response>
client_id=web-app
client_secret=<only for confidential>
```

Response: same shape as authorization_code grant. Refresh token is **rotated** (old one is revoked, new one issued).

```bash
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=<paste-refresh>" \
  -d "client_id=web-app"
```

#### Client Credentials grant

For machine-to-machine. Requires a **confidential** client. No user is involved — `sub` claim is the client_id.

```
grant_type=client_credentials
client_id=service-client
client_secret=service-secret-change-me
scope=openid                # optional, must be subset of client.scopes
```

Response `200`:
```json
{
  "token_type": "Bearer",
  "expires_in": 900,
  "access_token": "<JWT, sub=service-client>",
  "scope": "openid"
}
```

No `refresh_token` is issued (client can just request a new access_token anytime).

Errors:
- `unauthorized_client` — client is not confidential
- `invalid_client` — wrong/missing secret
- `invalid_scope` — requested scope not allowed for this client

```bash
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=service-client" \
  -d "client_secret=service-secret-change-me" \
  -d "scope=openid"
```

#### Device Code grant (RFC 8628)

For devices without a browser (TVs, CLIs). See `POST /oauth/device-authorization` for step 1.

```
grant_type=urn:ietf:params:oauth:grant-type:device_code
device_code=<from /oauth/device-authorization>
client_id=web-app
client_secret=<if confidential>
```

While the user hasn't approved yet, polling returns `400 authorization_pending`. After approval, the next poll returns full token response (same shape as authorization_code grant, including `id_token` if scope contained `openid`).

Polling errors (all `400` JSON):
- `authorization_pending` — user has not yet approved (keep polling)
- `slow_down` — (not implemented) reduce poll rate
- `access_denied` — user denied
- `expired_token` — device_code expired (5 min TTL)
- `invalid_grant` — device_code already consumed or unknown

```bash
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=<from-step-1>" \
  -d "client_id=web-app"
```

---

### `POST /oauth/device-authorization`

Step 1 of device code grant. Form-encoded. No user required.

```
client_id=web-app
scope=openid profile email   # optional, must be subset of client.scopes
```

Response `200`:
```json
{
  "device_code": "<opaque>",
  "user_code": "BCDF-GHJK",
  "verification_uri": "http://localhost:8080/oauth/device",
  "verification_uri_complete": "http://localhost:8080/oauth/device?user_code=BCDF-GHJK",
  "expires_in": 300,
  "interval": 5
}
```

The user navigates to `verification_uri` on another device, enters the `user_code`, and approves via `POST /oauth/device/verify`. Meanwhile the original device polls `/oauth/token`.

```bash
curl -X POST http://localhost:8080/oauth/device-authorization \
  -d "client_id=web-app" -d "scope=openid profile"
```

---

### `POST /oauth/device/verify`

Step 2 of device code grant. The user (already logged in) approves or denies the request from another device.

Requires session token (Bearer header or `session_token` cookie).

```
user_code=BCDF-GHJK
action=approve    # or "deny"
```

Response `200`:
```json
{ "message": "device authorized" }
```

Errors:
- `invalid_session` (401) — no active session
- `invalid_user_code` (400) — unknown code or already resolved
- `expired_token` (400) — user_code expired

```bash
curl -X POST http://localhost:8080/oauth/device/verify \
  -d "user_code=BCDF-GHJK" -d "action=approve" \
  -H "Authorization: Bearer <sessionToken>"
```

---

### `POST /oauth/revoke`

Form-encoded. Revokes a refresh token. Per RFC 7009, always responds 204 even if the token didn't exist (to prevent enumeration).

```
token=<refresh_token>
token_type_hint=refresh_token   # optional
client_id=web-app
client_secret=<if confidential>
```

Response `204 No Content` on success.

```bash
curl -X POST http://localhost:8080/oauth/revoke \
  -d "token=<refresh>" \
  -d "client_id=web-app"
```

---

### `POST /oauth/introspect`

RFC 7662 introspection. Tells you if a JWT access token is valid (signature + exp + iss).

```
token=<access_token JWT>
client_id=web-app
client_secret=<if confidential>
```

Response `200`:

```json
{ "active": true, "iss": "...", "sub": "...", "aud": "...", "exp": ..., "scope": "...", "roles": [...] }
```

Or for invalid/expired tokens:
```json
{ "active": false }
```

```bash
curl -X POST http://localhost:8080/oauth/introspect \
  -d "token=<accessToken>" \
  -d "client_id=web-app"
```

---

### `GET /oauth/logout`

OIDC RP-initiated logout. Terminates session and revokes all refresh tokens for that session.

Query parameters (all optional):

| Param | Notes |
|---|---|
| `id_token_hint` | JWT id_token. Used to identify the session via its `sid` claim |
| `post_logout_redirect_uri` | If provided, server redirects here after logout |
| `state` | Echoed back in redirect (if redirect_uri provided) |

Also accepts a session token via `Authorization: Bearer` header as fallback (if no id_token_hint).

Response: `200 { "message": "logged out" }` or `303` redirect to post_logout_redirect_uri.

```bash
# With id_token_hint
curl -i "http://localhost:8080/oauth/logout?id_token_hint=<idToken>&post_logout_redirect_uri=http://localhost:3000"

# With session token
curl -X GET http://localhost:8080/oauth/logout \
  -H "Authorization: Bearer <sessionToken>"
```

---

### `GET /userinfo`

OIDC userinfo. Requires JWT **access token** (not session token) with `openid` scope.

Response `200`:
```json
{
  "sub": "<user-uuid>",
  "email": "admin@gmail.com",        // only if scope contains email
  "email_verified": true,             // only if scope contains email
  "preferred_username": "admin",      // only if scope contains profile
  "given_name": "Admin",              // only if scope contains profile
  "family_name": "User",
  "name": "Admin User"
}
```

Errors:
- `401 invalid_token` — bad signature / expired / no sub claim / user not found
- `403 insufficient_scope` — token doesn't include `openid`

```bash
curl http://localhost:8080/userinfo \
  -H "Authorization: Bearer <accessToken>"
```

---

### `GET /.well-known/openid-configuration`

OIDC discovery doc. Public.

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

Sample response (abridged):
```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/oauth/authorize",
  "token_endpoint": "http://localhost:8080/oauth/token",
  "userinfo_endpoint": "http://localhost:8080/userinfo",
  "revocation_endpoint": "http://localhost:8080/oauth/revoke",
  "introspection_endpoint": "http://localhost:8080/oauth/introspect",
  "end_session_endpoint": "http://localhost:8080/oauth/logout",
  "jwks_uri": "http://localhost:8080/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256", "plain"],
  "claims_supported": [...]
}
```

---

### `GET /.well-known/jwks.json`

Public RSA public key in JWK format. Used by resource servers / OIDC clients to verify JWT signatures.

```bash
curl http://localhost:8080/.well-known/jwks.json
```

Sample response:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "<16-char fingerprint>",
      "n": "<base64url modulus>",
      "e": "AQAB"
    }
  ]
}
```

---

## Admin (RBAC-protected)

All `/admin/*` endpoints require:
1. Valid **session token** (Bearer) — `Authorization: Bearer <sessionToken>`
2. The session's user must have the `admin` role

Failures:
- `401 authentication required` — no/invalid session
- `403 forbidden` — session is valid but role is missing (includes required_roles in body)

### `GET /admin/ping`

Smoke test.

```json
{ "message": "hello admin", "username": "admin" }
```

```bash
curl http://localhost:8080/admin/ping \
  -H "Authorization: Bearer <sessionToken>"
```

---

### `GET /admin/roles`

List all roles seeded in the system.

Response `200`:
```json
[
  { "id": "<uuid>", "name": "admin", "description": "Full administrative access" },
  { "id": "<uuid>", "name": "user", "description": "Standard authenticated user" }
]
```

```bash
curl http://localhost:8080/admin/roles \
  -H "Authorization: Bearer <sessionToken>"
```

---

### `GET /admin/users`

List up to 100 most recent users.

Response `200`:
```json
[
  {
    "id": "<uuid>",
    "email": "admin@gmail.com",
    "username": "admin",
    "enabled": true,
    "emailVerified": true,
    "roles": ["admin"]
  }
]
```

```bash
curl http://localhost:8080/admin/users \
  -H "Authorization: Bearer <sessionToken>"
```

---

### `POST /admin/users/{userId}/roles/{roleName}`

Assign a role to a user. Idempotent.

Response `200`:
```json
{ "message": "role assigned", "roles": ["admin", "user"] }
```

Errors:
- `400 invalid userId` — not a valid UUID
- `404 user or role not found`

```bash
curl -X POST "http://localhost:8080/admin/users/<userId>/roles/user" \
  -H "Authorization: Bearer <sessionToken>"
```

---

### `DELETE /admin/users/{userId}/roles/{roleName}`

Remove a role from a user. Idempotent (no error if not assigned).

Response `200`:
```json
{ "message": "role revoked", "roles": ["user"] }
```

Errors:
- `400 invalid userId`
- `404 role not found`

```bash
curl -X DELETE "http://localhost:8080/admin/users/<userId>/roles/admin" \
  -H "Authorization: Bearer <sessionToken>"
```

---

## End-to-end OAuth + OIDC walkthrough

```bash
# 1. Login (get session token to act as the user inside /authorize)
SESSION=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@gmail.com","password":"admin123"}' \
  | jq -r .session.sessionToken)

# 2. Generate PKCE
VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
CHALLENGE=$(echo -n "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr -d "=+/")

# 3. Authorize → extract code from Location header
LOCATION=$(curl -s -o /dev/null -w "%{redirect_url}" \
  "http://localhost:8080/oauth/authorize?response_type=code&client_id=web-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid+profile+email&state=xyz&nonce=abc&code_challenge=$CHALLENGE&code_challenge_method=S256" \
  -H "Authorization: Bearer $SESSION")

CODE=$(echo "$LOCATION" | grep -oP 'code=\K[^&]+')

# 4. Exchange code → tokens
TOKENS=$(curl -s -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=$CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=web-app" \
  -d "code_verifier=$VERIFIER")

ACCESS=$(echo "$TOKENS" | jq -r .access_token)
ID=$(echo "$TOKENS" | jq -r .id_token)
REFRESH=$(echo "$TOKENS" | jq -r .refresh_token)

echo "Access token claims:"
echo "$ACCESS" | cut -d. -f2 | base64 -d 2>/dev/null | jq

# 5. Call userinfo with access token
curl http://localhost:8080/userinfo -H "Authorization: Bearer $ACCESS"

# 6. Introspect
curl -X POST http://localhost:8080/oauth/introspect \
  -d "token=$ACCESS" -d "client_id=web-app"

# 7. Refresh
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH" \
  -d "client_id=web-app"
```

## Default bootstrap state

After first startup, you'll have:

| Entity | Value |
|---|---|
| Admin user email | `admin@gmail.com` |
| Admin user password | `admin123` |
| Admin user role | `admin` |
| Seeded roles | `admin`, `user` |
| Bootstrap public client | `web-app` (type=public, PKCE required, scopes=openid+profile+email, redirect=`http://localhost:3000/callback`, grants=authorization_code+refresh_token) |
| Bootstrap confidential client | `service-client` (secret=`service-secret-change-me`, type=confidential, scopes=openid+profile+email, grants=client_credentials) |
| Access token TTL | 900 seconds (15 min) |
| ID token TTL | 3600 seconds (1 hour) |
| Refresh token TTL | 30 days |
| Session TTL | 8 hours |
| Device code TTL | 300 seconds (5 min) |

## Endpoints summary

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/auth/signup` | Public | Creates unverified user |
| POST | `/auth/verify-email` | Public | With verification token |
| POST | `/auth/login` | Public | JSON, returns session token |
| GET | `/login` | Public | HTML form |
| POST | `/login` | Public | Form, sets `session_token` cookie |
| GET | `/auth/me` | Session | Current user info |
| POST | `/auth/logout` | Session | Ends session |
| GET | `/oauth/authorize` | Session (redirects to `/login` if missing) | OAuth/OIDC start |
| POST | `/oauth/token` | (Public; client_secret if confidential) | All grants |
| POST | `/oauth/revoke` | (Public; client_secret if confidential) | RFC 7009 |
| POST | `/oauth/introspect` | (Public; client_secret if confidential) | RFC 7662 |
| GET | `/oauth/logout` | Session or id_token_hint | RP-initiated logout |
| POST | `/oauth/device-authorization` | Public | Device flow step 1 |
| POST | `/oauth/device/verify` | Session | Device flow step 2 (approve/deny) |
| GET | `/userinfo` | JWT access_token with `openid` scope | OIDC |
| GET | `/.well-known/openid-configuration` | Public | OIDC discovery |
| GET | `/.well-known/jwks.json` | Public | Public keys (JWKS) |
| GET | `/admin/ping` | Session with `admin` role | Smoke test |
| GET | `/admin/roles` | Session with `admin` role | List all roles |
| GET | `/admin/users` | Session with `admin` role | List up to 100 users |
| POST | `/admin/users/{id}/roles/{name}` | Session with `admin` role | Assign role |
| DELETE | `/admin/users/{id}/roles/{name}` | Session with `admin` role | Revoke role |

## Troubleshooting

### Quarkus fails to start with "Datasource '\<default\>' was deactivated"

Postgres not reachable or env vars empty. Verify:
```bash
psql "postgresql://postgres:erika@localhost:15552/xerika-java" -c '\dt'
```
If that fails, fix the DB before starting Quarkus. If you use different host/port/user, override via `DB_URL`, `DB_USER`, `DB_PASS`.

### Quarkus fails to start with "Failed to load config value of type String for: auth.jwt.keys.dir"

Old `application.properties` style. Update `RsaKeyProvider` to use `Optional<String>` (already fixed on current main).

### `POST /auth/login` returns `401 invalid credentials` for a user you just created

`LoginService` rejects users with `emailVerified=false`. Either complete `POST /auth/verify-email` first, or flip the column in the DB manually for testing:
```sql
UPDATE users SET email_verified = true WHERE email = 'alice@example.com';
```
The bootstrapped `admin@gmail.com` is pre-verified.

### `GET /userinfo` returns `401 invalid_token` with a freshly issued access token

Most common cause: server restarted and the previous keypair was deleted. The token was signed with the old key, but the server now has a new public key.
- Default key directory is `~/.xerika/auth/keys/` (persisted across restarts — should not cause this).
- If you cleared the directory, issued tokens are invalidated. Get a new one via `/oauth/authorize` → `/oauth/token`.

### `GET /admin/*` returns `403 forbidden` despite being logged in

The session's user does not have the `admin` role. Check:
```bash
curl http://localhost:8080/auth/me -H "Authorization: Bearer <sessionToken>"
# look for "roles": ["admin"]
```
If empty, assign the role directly via SQL or have an admin call `POST /admin/users/{id}/roles/admin`.

### Browser visits `/oauth/authorize` and gets redirected to `/login`

Expected. The OAuth flow requires an authenticated session. After login, the user is sent back to `/oauth/authorize` to complete the flow.

To bypass for testing (e.g. simulating an already-authenticated session), pass the session token directly:
```bash
curl -i "http://localhost:8080/oauth/authorize?..." -H "Authorization: Bearer <sessionToken>"
```

### Refresh token grant returns `invalid_grant: Refresh token is revoked or expired`

Refresh tokens are **rotated** on every use. The previous one is revoked the moment the new pair is issued. If you accidentally retry a refresh request, the old token is already revoked.

### `POST /oauth/token` for `client_credentials` returns `unauthorized_client`

The client must be `type=confidential` (i.e., it has a secret). The bootstrap `web-app` is **public** (no secret) and cannot use `client_credentials`. Use `service-client` instead.

### `POST /oauth/device-authorization` succeeded but polling `/oauth/token` keeps returning `authorization_pending`

Expected until a user calls `POST /oauth/device/verify` with the `user_code` and an active session. Per RFC 8628, polling should respect the `interval` returned (default 5s) and stop after `expires_in` (300s).

## Authorization annotations (internal pattern)

For protecting endpoints, the server uses two custom annotations on JAX-RS resources:

- **`@RequiresRole(...)`** (from `com.xerika.auth.role`) — session-based RBAC check. Looks up roles from DB via session token. Used by `/admin/*`.
- **`@RequiresScope(...)`** (from `com.xerika.auth.oauth`) — JWT-based scope check. Reads `scope` claim from access token. Used by `/userinfo`. The validated claims are exposed to the resource via `ContainerRequestContext.getProperty(ScopeFilter.CLAIMS_PROPERTY)`.

Both accept multi-value (any-of semantics): `@RequiresRole({"admin", "auditor"})`, `@RequiresScope({"openid", "profile"})`. Single value works as backward-compatible shorthand.
