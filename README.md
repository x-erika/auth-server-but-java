# auth-server-but-java

OAuth 2.0 + OpenID Connect authorization server, built on Quarkus.

Implements the six core auth primitives: **OAuth2, OIDC, JWT, PKCE, RBAC, SSO** — runnable end-to-end with admin bootstrap, browser-based login, and a companion Next.js admin UI ([`auth-admin-but-java`](../auth-admin-but-java)).

## Quick start

```bash
# 1. Postgres running locally (port + DB name configurable; defaults below)
docker run -d --name auth-pg \
  -p 15552:5432 \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=erika \
  -e POSTGRES_DB=xerika-java \
  postgres:16

# 2. Start the auth server (dev mode with live reload)
./mvnw quarkus:dev
# → Listening on http://localhost:8080
# → Bootstrap admin: admin@gmail.com / admin123
# → RSA keypair generated at ~/.xerika/auth/keys/

# 3. Try the browser flow
open http://localhost:8080/login
```

Defaults from `application.properties` (override via env vars):

| Property | Default | Env var |
|---|---|---|
| `quarkus.datasource.jdbc.url` | `jdbc:postgresql://localhost:15552/xerika-java?sslmode=disable` | `DB_URL` |
| `quarkus.datasource.username` | `postgres` | `DB_USER` |
| `quarkus.datasource.password` | `erika` | `DB_PASS` |
| `auth.issuer.url` | `http://localhost:8080` | — |
| `auth.jwt.access-token-ttl-seconds` | `900` | — |
| `auth.jwt.id-token-ttl-seconds` | `3600` | — |
| `auth.jwt.keys.dir` | `~/.xerika/auth/keys` | — |

## Documentation

| File | Contents |
|---|---|
| [`API.md`](./API.md) | Endpoint reference (request/response shapes, curl examples, end-to-end OAuth walkthrough) |
| `src/main/resources/db/migration/` | Flyway migrations (V1 schema → V4 device codes) |

## Feature coverage

| Feature | Coverage | What's implemented | What's deferred |
|---|---|---|---|
| **OAuth 2.0** | 100% | authorization_code, refresh_token (with rotation), client_credentials, device_code (RFC 8628), revoke (RFC 7009), introspect (RFC 7662) | — |
| **OIDC** | 92% | id_token, /userinfo, discovery doc, JWKS, RP-initiated logout, nonce, auth_time, prompt, max_age | consent screen, request object, claims parameter |
| **JWT** | 90% | RS256 with persistent RSA keypair, full claims (iss/sub/aud/exp/iat/jti/...), JwtValidator, kid header | multi-key rotation |
| **PKCE** | 90% | S256 + plain, enforced for public clients | — |
| **RBAC** | 90% | Role entity + assignment, `@RequiresRole` filter, `@RequiresScope` (JWT scope-based), roles claim in JWT, admin endpoints to manage role assignment | role hierarchy |
| **SSO** | 65% | Shared session (cookie + Bearer), browser-redirect OAuth flow, RP-initiated logout, auth_time + sid in tokens | consent screen, back-channel logout, front-channel logout |

## Architecture

Package-by-feature layout under `com.xerika.auth`:

```
admin/          GET/POST/DELETE /admin/* — user & role administration
bootstrap/      Idempotent startup seeders (admin user, roles, default clients)
client/         OAuth client entity + repository + redirect URIs
common/
  crypto/         Argon2Hasher, JwtSigner, JwtValidator, RsaKeyProvider, Sha256, RandomTokens
  web/            BearerExtractor (header + cookie token resolution)
login/          /auth/login (JSON) + /login (HTML, Qute) + LoginService
oauth/
  authorize/      AuthorizeFlow, AuthCodeStore (DB-backed), AuthorizationCode
  device/         DeviceFlow, DeviceAuthorization (RFC 8628)
  logout/         LogoutFlow (RP-initiated)
  pkce/           PkceVerifier (S256 + plain)
  token/          TokenFlow, TokenIssuer, RefreshToken, IntrospectFlow, RevokeFlow
  OAuthResource   /oauth/* JAX-RS endpoints
  Scopes          shared parse/subset utility
  RequiresScope   annotation + ScopeFilter (JWT-based authz)
oidc/           /userinfo, /.well-known/openid-configuration, /.well-known/jwks.json
role/           Role + RoleRepository + @RequiresRole + RoleFilter (session-based authz)
session/        UserSession + SessionService (8-hour TTL)
signup/         /auth/signup + /auth/verify-email + EmailVerification
user/           User + Credential entities + repositories
```

Each subpackage is self-contained: entity, repository, flow/service, and DTOs all live next to each other, not split by layer.

## Token model

- **Session token** (opaque, 8h) — for browser/admin sessions. Accepted via `Authorization: Bearer`, `X-Session-Token` header, or `session_token` cookie.
- **Access token** (JWT RS256, 15min) — for resource server APIs. Carries `sub`, `aud`, `iss`, `exp`, `iat`, `jti`, `scope`, `roles`, `sid`, `email`, `username`.
- **Refresh token** (opaque, 30 days, hashed in DB) — rotated on each use.
- **ID token** (JWT RS256, 1h) — OIDC identity assertion, issued only with `openid` scope.

JWTs are signed with a persistent RSA-2048 keypair stored at `~/.xerika/auth/keys/`. The matching public key is published at `/.well-known/jwks.json` with a deterministic `kid` (SHA-256 fingerprint).

## Running tests

```bash
./mvnw test
```

29 unit tests covering Argon2 round-trips, SHA-256 properties, scope parsing, PKCE verification, random token uniqueness. No DB required — pure-function tests.

## Project status

This is a **learning project** showcasing the core auth primitives. It is **not production-ready**:

- Tokens issued under one keypair are invalidated when the keypair file is deleted (no key rotation strategy)
- No consent screen — users implicitly authorize all requested scopes
- Email verification token is returned in the signup API response (in production, would be emailed)
- No rate limiting / brute-force protection
- No audit log
- Default bootstrap credentials are committed to the repo (`admin@gmail.com / admin123`, `service-client / service-secret-change-me`)

See `API.md` § "Deferred" notes for the full list of unfinished items.

---

Built with Quarkus 3.30, Java 21, PostgreSQL 16, Flyway, Hibernate ORM, BouncyCastle (Argon2), Smallrye JWT Build, Qute (templates).
