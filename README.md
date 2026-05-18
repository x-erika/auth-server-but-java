# auth-server-but-java

OAuth 2.0 + OpenID Connect authorization server, built on Quarkus.

Implements the six core auth primitives: **OAuth2, OIDC, JWT, PKCE, RBAC, SSO** — runnable end-to-end with admin bootstrap, browser-based login, and a companion Next.js admin UI ([`auth-admin-but-java`](https://github.com/x-erika/auth-admin-but-java)). Backed by Postgres (durable state) + Redis (transient artifacts, hot-path cache, rate-limit counters).

## Quick start

Point at a Postgres instance and a Redis instance (override via `DB_URL` / `DB_USER` / `DB_PASS` / `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASS` or edit `application.properties`), then:

```bash
./mvnw quarkus:dev
```

On first boot the server runs all Flyway migrations, seeds the `admin` and
`user` roles plus a bootstrap admin account, generates an RSA-2048 keypair
under `~/.xerika/auth/keys/`, and starts listening on
[`http://localhost:8080`](http://localhost:8080) with `/login` as the browser
entry point.

Readiness probe: `GET /q/health/ready` (returns `UP` only when both Postgres and Redis are reachable).

## Documentation

| File | Contents |
|---|---|
| [`API.md`](./API.md) | Endpoint reference (request/response shapes, curl examples, end-to-end OAuth walkthrough) |
| `src/main/resources/db/migration/` | Flyway migrations (V1 schema → V8: device codes, role hierarchy, consent, logout URIs, claims request; V9: drop tables now backed by Redis) |

## Feature coverage

| Feature | What's implemented |
|---|---|
| **OAuth 2.0** | authorization_code, refresh_token (with rotation), client_credentials, device_code (RFC 8628), revoke (RFC 7009), introspect (RFC 7662) |
| **OIDC** | id_token, /userinfo, discovery doc, JWKS, RP-initiated logout, nonce, auth_time, prompt, max_age, consent screen, request object (HS256 + none), claims parameter |
| **JWT** | RS256 with persistent RSA keypair, full claims (iss/sub/aud/exp/iat/jti/...), JwtValidator, kid header, multi-key rotation with kid-based key selection on verify |
| **PKCE** | S256 + plain, enforced for public clients |
| **RBAC** | Role entity + assignment, role hierarchy (parent_id, cycle-checked) with recursive effective-role resolution, `@RequiresRole` filter, `@RequiresScope` (JWT scope-based), roles claim in JWT, admin endpoints to manage role assignment & hierarchy |
| **SSO** | Shared session (cookie + Bearer), browser-redirect OAuth flow, consent screen, RP-initiated logout, front-channel logout (iframe propagation), back-channel logout (signed logout_token POST), auth_time + sid in tokens |
| **Rate limiting** | Lua-atomic INCR+EXPIRE on `/auth/login` (per email + per IP), `/auth/signup` (per IP), `/auth/verify-email` (per IP), `/oauth/device-authorization` (per client_id). Fail-open if Redis is down. Returns 429 with `Retry-After`. |

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
| [RFC 6585](https://datatracker.ietf.org/doc/html/rfc6585) | Additional HTTP Status Codes | `429 Too Many Requests` + `Retry-After` for rate limits |

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

## Storage layout

Two stores, with a clear split of responsibilities:

| Concern | Postgres (durable) | Redis (volatile / hot) |
|---|---|---|
| Users, credentials, roles, role assignments, consents | Source of truth | — |
| Clients + redirect URIs | Source of truth | Cache-aside (`client:<client_id>`, TTL ~30min ±10% jitter) |
| Sessions | Source of truth | Cache-aside (`session:<sha256(token)>`, TTL = remaining session lifetime) |
| Refresh tokens, email verifications | Source of truth | — |
| Authorization codes (single-use, ~10min TTL) | — | Redis-only (`authcode:<code>`, Lua GET+DEL atomic consume) |
| Device authorizations + user_code lookup | — | Redis-only Hash with two-key pattern (`device:dc:<deviceCode>` + `device:uc:<userCode>` pointer) |
| Pending consent state | — | Redis-only (`pending:<requestId>`) |
| Rate-limit counters | — | Redis-only (`rl:*`, Lua INCR+EXPIRE) |

Cache-aside writes invalidate Redis via `TransactionSynchronizationRegistry.afterCompletion(STATUS_COMMITTED)` so a concurrent reader cannot populate the cache with pre-commit data. Read-side falls back to Postgres on any Redis exception (fail-open). Session delete DELs Redis first and throws on failure (fail-closed for logout, prevents post-delete cache hits leaving users authenticated).

Redis is configured with `maxmemory 256mb` + `maxmemory-policy volatile-lru` so only TTL-bearing keys are evictable; cache-aside keys (sessions, clients) can be evicted safely since Postgres remains authoritative.

## Architecture

Package-by-feature layout under `com.xerika.auth`:

```
admin/          GET/POST/DELETE /admin/* — user/role administration, role hierarchy, signing key rotation
bootstrap/      Idempotent startup seeders (admin user, roles + hierarchy, default clients)
client/         OAuth client entity + repository (cache-aside via ClientSnapshot DTO) + redirect URIs
common/
  crypto/         Argon2Hasher, JwtSigner, JwtValidator, RsaKeyProvider (multi-key), Sha256, RandomTokens
  ratelimit/      RateLimiter (Lua INCR+EXPIRE, fail-open), RateLimitDecision, 429+Retry-After helper
  redis/          RedisKeys (key namespacing), RedisJson (Jackson with java-time + tolerant deser),
                  RedisLua (SCRIPT LOAD + EVALSHA with NOSCRIPT fallback)
  web/            BearerExtractor (header + cookie token resolution)
login/          /auth/login (JSON, rate-limited per email + IP) + /login (HTML, Qute) + LoginService
oauth/
  authorize/      AuthorizeFlow, AuthCodeStore (Redis-only, single-use via Lua GET+DEL), AuthorizationCode (POJO)
  consent/        ConsentService, UserConsent, PendingAuthorizationStore (Redis-only), /consent (Qute)
  device/         DeviceFlow, DeviceAuthorization (POJO), DeviceAuthorizationRepository
                  (Redis Hash + two-key pattern: deviceCode blob + userCode pointer)
  logout/         LogoutFlow, BackchannelLogoutNotifier (front- + back-channel)
  pkce/           PkceVerifier (S256 + plain)
  token/          TokenFlow, TokenIssuer, RefreshToken, IntrospectFlow, RevokeFlow
  OAuthResource   /oauth/* JAX-RS endpoints (device-authorization rate-limited per client_id)
  Scopes          shared parse/subset utility
  RequiresScope   annotation + ScopeFilter (JWT-based authz)
oidc/           /userinfo, /.well-known/openid-configuration, /.well-known/jwks.json (all active keys)
role/           Role (with parent_id) + RoleRepository (effective-role walk) + @RequiresRole + RoleFilter
session/        UserSession + SessionService (8-hour TTL) + SessionRepository (cache-aside via SessionSnapshot DTO)
signup/         /auth/signup + /auth/verify-email + EmailVerification (both endpoints rate-limited per IP)
user/           User + Credential entities + repositories
```

Each subpackage is self-contained: entity, repository, flow/service, and DTOs all live next to each other, not split by layer.

## Token model

- **Session token** (opaque, 8h) — for browser/admin sessions. Accepted via `Authorization: Bearer`, `X-Session-Token` header, or `session_token` cookie. Cached in Redis by `sha256(token)`; Postgres is source of truth.
- **Access token** (JWT RS256, 15min) — for resource server APIs. Carries `sub`, `aud`, `iss`, `exp`, `iat`, `jti`, `scope`, `roles`, `sid`, `email`, `username`.
- **Refresh token** (opaque, 30 days, hashed in DB) — rotated on each use.
- **ID token** (JWT RS256, 1h) — OIDC identity assertion, issued only with `openid` scope.

JWTs are signed with a persistent RSA-2048 keypair stored at `~/.xerika/auth/keys/`, named `<kid>.private.pem` / `<kid>.public.pem` per key, with `active.kid` selecting the current signing key. `POST /admin/keys/rotate` generates a new keypair and rotates the active kid in place — old kids remain in the JWKS so tokens already in flight continue to verify until they expire.

## Project status

This is a **learning project** showcasing the core auth primitives. It is **not production-ready**:

- Email verification token is returned in the signup API response (in production, would be emailed)
- No audit log
- Request object verification only supports `HS256` (with `client_secret`) and `none` (public clients) — no asymmetric per-client keys / JWKS-by-reference
- Default bootstrap credentials are committed to the repo — rotate before exposing the server beyond localhost
- `X-Forwarded-For` is trusted as-is for IP-based rate limits (needs trusted-proxy configuration before exposing to the internet)
- Successful logins also consume the per-email rate-limit budget (intentional simplicity; can be split into failure-only buckets later)
- User profile updates via admin do not invalidate cached sessions — email/username changes appear stale until session TTL or logout

See `API.md` § "Deferred" notes for the full list of unfinished items.

---

Built with Quarkus 3.30, Java 21, PostgreSQL 17, Redis 6, Flyway, Hibernate ORM, BouncyCastle (Argon2), Smallrye JWT Build, Smallrye Health, Qute (templates).
