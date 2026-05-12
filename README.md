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
| `src/main/resources/db/migration/` | Flyway migrations (V1 schema → V8: device codes, role hierarchy, consent, logout URIs, claims request) |

## Feature coverage

| Feature | Coverage | What's implemented |
|---|---|---|
| **OAuth 2.0** | 100% | authorization_code, refresh_token (with rotation), client_credentials, device_code (RFC 8628), revoke (RFC 7009), introspect (RFC 7662) |
| **OIDC** | 100% | id_token, /userinfo, discovery doc, JWKS, RP-initiated logout, nonce, auth_time, prompt, max_age, consent screen, request object (HS256 + none), claims parameter |
| **JWT** | 100% | RS256 with persistent RSA keypair, full claims (iss/sub/aud/exp/iat/jti/...), JwtValidator, kid header, multi-key rotation with kid-based key selection on verify |
| **PKCE** | 100% | S256 + plain, enforced for public clients |
| **RBAC** | 100% | Role entity + assignment, role hierarchy (parent_id, cycle-checked) with recursive effective-role resolution, `@RequiresRole` filter, `@RequiresScope` (JWT scope-based), roles claim in JWT, admin endpoints to manage role assignment & hierarchy |
| **SSO** | 100% | Shared session (cookie + Bearer), browser-redirect OAuth flow, consent screen, RP-initiated logout, front-channel logout (iframe propagation), back-channel logout (signed logout_token POST), auth_time + sid in tokens |

## Standards

### OAuth 2.0 (IETF RFCs)

| RFC | Title | What it covers here |
|---|---|---|
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | The OAuth 2.0 Authorization Framework | Core grants: `authorization_code`, `refresh_token`, `client_credentials` |
| [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) | Bearer Token Usage | `Authorization: Bearer …` header |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE | `code_challenge` / `code_verifier` with S256 + plain |
| [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) | Token Revocation | `POST /oauth/revoke` |
| [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) | Token Introspection | `POST /oauth/introspect` |
| [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) | Device Authorization Grant | `POST /oauth/device-authorization` + `POST /oauth/device/verify` |

### JWT / JOSE (IETF RFCs)

| RFC | Title | What it covers here |
|---|---|---|
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) | JSON Web Token (JWT) | Token structure: header.payload.signature |
| [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) | JSON Web Signature (JWS) | Signing wire format, `kid` in header |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) | JSON Web Key (JWK) | JWKS published at `/.well-known/jwks.json` |
| [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) | JSON Web Algorithms (JWA) | `RS256` for id_token/access_token, `HS256` for request objects |

### OpenID Connect (OpenID Foundation specs)

| Spec | What it covers here |
|---|---|
| [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | `id_token`, `/userinfo`, `nonce`, `auth_time`, `prompt`, `max_age`, `request` parameter, `claims` parameter, consent |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | `/.well-known/openid-configuration` |
| [OIDC RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | `/oauth/logout` with `id_token_hint` + `post_logout_redirect_uri` |
| [OIDC Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html) | iframe-based propagation to registered `frontchannel_logout_uri` |
| [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | Signed `logout_token` POST to registered `backchannel_logout_uri` |

### RBAC and SSO

Neither is a single IETF RFC. RBAC implementation follows the formal model from **NIST INCITS 359-2012** (roles with hierarchical inheritance, role-permission assignment, session-role activation). SSO here is a pattern realised through the combination of shared session cookies + the OAuth/OIDC flows above — not a standalone wire protocol.

## Architecture

Package-by-feature layout under `com.xerika.auth`:

```
admin/          GET/POST/DELETE /admin/* — user/role administration, role hierarchy, signing key rotation
bootstrap/      Idempotent startup seeders (admin user, roles + hierarchy, default clients)
client/         OAuth client entity + repository + redirect URIs (incl. front/backchannel logout URIs)
common/
  crypto/         Argon2Hasher, JwtSigner, JwtValidator, RsaKeyProvider (multi-key), Sha256, RandomTokens
  web/            BearerExtractor (header + cookie token resolution)
login/          /auth/login (JSON) + /login (HTML, Qute) + LoginService
oauth/
  authorize/      AuthorizeFlow, AuthCodeStore (DB-backed), AuthorizationCode, RequestObjectParser, ClaimsRequest
  consent/        ConsentService, UserConsent, PendingAuthorizationStore, /consent (Qute)
  device/         DeviceFlow, DeviceAuthorization (RFC 8628)
  logout/         LogoutFlow, BackchannelLogoutNotifier (front- + back-channel)
  pkce/           PkceVerifier (S256 + plain)
  token/          TokenFlow, TokenIssuer, RefreshToken, IntrospectFlow, RevokeFlow
  OAuthResource   /oauth/* JAX-RS endpoints
  Scopes          shared parse/subset utility
  RequiresScope   annotation + ScopeFilter (JWT-based authz)
oidc/           /userinfo, /.well-known/openid-configuration, /.well-known/jwks.json (all active keys)
role/           Role (with parent_id) + RoleRepository (effective-role walk) + @RequiresRole + RoleFilter
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

JWTs are signed with a persistent RSA-2048 keypair stored at `~/.xerika/auth/keys/`, named `<kid>.private.pem` / `<kid>.public.pem` per key, with `active.kid` selecting the current signing key. `POST /admin/keys/rotate` generates a new keypair and rotates the active kid in place — old kids remain in the JWKS so tokens already in flight continue to verify until they expire.

## Running tests

```bash
./mvnw test
```

29 unit tests covering Argon2 round-trips, SHA-256 properties, scope parsing, PKCE verification, random token uniqueness. No DB required — pure-function tests.

## Project status

This is a **learning project** showcasing the core auth primitives. It is **not production-ready**:

- Email verification token is returned in the signup API response (in production, would be emailed)
- No rate limiting / brute-force protection
- No audit log
- Request object verification only supports `HS256` (with `client_secret`) and `none` (public clients) — no asymmetric per-client keys / JWKS-by-reference
- Default bootstrap credentials are committed to the repo — rotate before exposing the server beyond localhost

See `API.md` § "Deferred" notes for the full list of unfinished items.

---

Built with Quarkus 3.30, Java 21, PostgreSQL 16, Flyway, Hibernate ORM, BouncyCastle (Argon2), Smallrye JWT Build, Qute (templates).
