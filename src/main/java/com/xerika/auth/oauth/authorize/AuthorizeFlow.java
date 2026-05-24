package com.xerika.auth.oauth.authorize;

import com.xerika.auth.client.Client;
import com.xerika.auth.client.ClientRepository;
import com.xerika.auth.common.crypto.RandomTokens;
import com.xerika.auth.oauth.Scopes;
import com.xerika.auth.oauth.consent.ConsentService;
import com.xerika.auth.oauth.consent.PendingAuthorization;
import com.xerika.auth.oauth.consent.PendingAuthorizationStore;
import com.xerika.auth.oauth.pkce.PkceVerifier;
import com.xerika.auth.session.SessionService;
import com.xerika.auth.session.UserSession;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@ApplicationScoped
public class AuthorizeFlow {

    private static final int AUTH_CODE_TTL_MINUTES = 3;
    private static final int AUTH_CODE_BYTES = 48;
    private static final int CONSENT_REQUEST_TTL_MINUTES = 10;
    // After a re-auth via /login, the OP treats prompt=login as already-satisfied for
    // this long. Picks up the redirect back to /oauth/authorize without re-prompting.
    // Kept short (~10s) so a phishing flow that tricks a user into a fresh login
    // can't piggyback on the grace window beyond the natural redirect round-trip.
    private static final int REAUTH_GRACE_SECONDS = 10;

    @Inject
    ClientRepository clientRepository;

    @Inject
    SessionService sessionService;

    @Inject
    AuthCodeStore authCodeStore;

    @Inject
    PkceVerifier pkceVerifier;

    @Inject
    ConsentService consentService;

    @Inject
    PendingAuthorizationStore pendingAuthorizationStore;

    public AuthorizeResult authorize(
        String sessionToken,
        String clientId,
        String redirectUri,
        String responseType,
        String scope,
        String state,
        String nonce,
        String prompt,
        Long maxAge,
        String codeChallenge,
        String codeChallengeMethod,
        String claimsJson
    ) {
        if (!"code".equals(responseType)) {
            return AuthorizeResult.error("unsupported_response_type", "Only response_type=code is supported");
        }

        if (clientId == null || clientId.isBlank() || redirectUri == null || redirectUri.isBlank()) {
            return AuthorizeResult.error("invalid_request", "client_id and redirect_uri are required");
        }

        Set<String> prompts = parsePrompt(prompt);
        boolean promptNone = prompts.contains("none");
        boolean promptLogin = prompts.contains("login");
        boolean promptConsent = prompts.contains("consent");

        UserSession session = sessionService.findActiveSession(sessionToken).orElse(null);
        // prompt=login: force re-auth, but only if the session is older than the
        // re-auth grace window. Without this guard, every redirect-back from /login
        // would re-trigger the prompt and loop forever.
        boolean recentlyAuthenticated = session != null && session.createdAt != null
            && Duration.between(session.createdAt, LocalDateTime.now()).getSeconds()
                < REAUTH_GRACE_SECONDS;
        if (session == null || (promptLogin && !recentlyAuthenticated)) {
            return AuthorizeResult.error(
                promptNone ? "login_required" : "invalid_session",
                promptLogin ? "prompt=login requires re-authentication" : "Login required"
            );
        }

        if (maxAge != null && session.createdAt != null) {
            long ageSeconds = Duration.between(session.createdAt, LocalDateTime.now()).getSeconds();
            if (ageSeconds > maxAge) {
                return AuthorizeResult.error(
                    promptNone ? "login_required" : "invalid_session",
                    "Session age " + ageSeconds + "s exceeds max_age " + maxAge + "s"
                );
            }
        }

        Client client = clientRepository.findByClientId(clientId).orElse(null);
        if (client == null || !client.enabled) {
            return AuthorizeResult.error("unauthorized_client", "Unknown or disabled client");
        }

        // JAR (Request Object, RFC 9101) support removed: the previous HS256
        // implementation required client.clientSecret as the HMAC key, which is
        // now Argon2-hashed at rest — verification could never succeed for
        // anything but legacy plaintext rows. A correct JAR implementation
        // needs either a separate raw-secret column or RS256 against the
        // client's registered JWKS; we ship neither.

        if (!clientRepository.isRedirectUriAllowed(client.id, redirectUri)) {
            return AuthorizeResult.error("invalid_request", "redirect_uri is not registered");
        }
        // From here on, redirect_uri is validated against the client's registered
        // list, so RFC 6749 §4.1.2.1 says errors MUST go back via redirect with
        // ?error=...&state=..., not as a JSON 400.

        if (!Scopes.isSubsetOf(scope, client.scopes)) {
            return errorRedirect(redirectUri, state, "invalid_scope",
                "Requested scope is not allowed for this client");
        }

        // Validate code_challenge_method whenever a challenge is present, regardless of
        // client.pkceRequired. Pairs with TokenFlow.fromAuthorizationCode, which now
        // verifies any stored challenge — closes the downgrade where a non-PKCE-required
        // client could submit a challenge with an unsupported method and have it silently
        // dropped at /token.
        String resolvedMethod = null;
        boolean hasChallenge = codeChallenge != null && !codeChallenge.isBlank();
        if (hasChallenge) {
            resolvedMethod = (codeChallengeMethod == null || codeChallengeMethod.isBlank())
                ? "plain"
                : codeChallengeMethod;
            if (!pkceVerifier.isMethodSupported(resolvedMethod)) {
                return errorRedirect(redirectUri, state, "invalid_request",
                    "Unsupported code_challenge_method");
            }
        } else if (client.pkceRequired) {
            return errorRedirect(redirectUri, state, "invalid_request",
                "code_challenge is required");
        }

        boolean hasConsent = !promptConsent && consentService.hasConsent(session.user.id, client.id, scope);
        if (!hasConsent) {
            if (promptNone) {
                return errorRedirect(redirectUri, state, "consent_required",
                    "Consent is required but prompt=none was specified");
            }

            PendingAuthorization pending = new PendingAuthorization();
            pending.requestId = RandomTokens.urlSafe(24);
            pending.sessionId = session.id;
            pending.userId = session.user.id;
            pending.clientId = client.clientId;
            pending.redirectUri = redirectUri;
            pending.responseType = responseType;
            pending.scope = scope;
            pending.state = state;
            pending.nonce = nonce;
            pending.prompt = prompt;
            pending.maxAge = maxAge;
            pending.codeChallenge = codeChallenge;
            pending.codeChallengeMethod = resolvedMethod;
            pending.claimsRequested = claimsJson;
            pending.expiresAt = LocalDateTime.now().plusMinutes(CONSENT_REQUEST_TTL_MINUTES);
            pendingAuthorizationStore.put(pending);

            return AuthorizeResult.consentRequired(pending.requestId);
        }

        return issueCode(session.id, session.user.id, client, redirectUri, scope, state, nonce,
            codeChallenge, resolvedMethod, claimsJson);
    }

    public AuthorizeResult completeAfterConsent(PendingAuthorization pending) {
        Client client = clientRepository.findByClientId(pending.clientId).orElse(null);
        if (client == null || !client.enabled) {
            return AuthorizeResult.error("unauthorized_client", "Unknown or disabled client");
        }
        if (!clientRepository.isRedirectUriAllowed(client.id, pending.redirectUri)) {
            return AuthorizeResult.error("invalid_request", "redirect_uri is not registered");
        }

        consentService.grant(pending.userId, client.id, pending.scope);

        return issueCode(pending.sessionId, pending.userId, client, pending.redirectUri,
            pending.scope, pending.state, pending.nonce,
            pending.codeChallenge, pending.codeChallengeMethod, pending.claimsRequested);
    }

    private AuthorizeResult issueCode(
        UUID sessionId,
        UUID userId,
        Client client,
        String redirectUri,
        String scope,
        String state,
        String nonce,
        String codeChallenge,
        String codeChallengeMethod,
        String claimsRequested
    ) {
        // Expired authorization codes are reaped by Redis TTL automatically.

        String code = RandomTokens.urlSafe(AUTH_CODE_BYTES);
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(AUTH_CODE_TTL_MINUTES);

        AuthorizationCode authCode = new AuthorizationCode();
        authCode.code = code;
        authCode.clientId = client.clientId;
        authCode.userId = userId;
        authCode.sessionId = sessionId;
        authCode.redirectUri = redirectUri;
        authCode.scope = scope;
        authCode.state = state;
        authCode.nonce = nonce;
        authCode.codeChallenge = codeChallenge;
        authCode.codeChallengeMethod = codeChallengeMethod;
        authCode.claimsRequested = claimsRequested;
        authCode.expiresAt = expiresAt;
        authCodeStore.put(authCode);

        String location = buildRedirect(redirectUri, Map.of(
            "code", code,
            "state", state == null ? "" : state
        ));

        return AuthorizeResult.success(URI.create(location));
    }

    private AuthorizeResult errorRedirect(String redirectUri, String state, String error, String description) {
        java.util.LinkedHashMap<String, String> params = new java.util.LinkedHashMap<>();
        params.put("error", error);
        if (description != null && !description.isBlank()) {
            params.put("error_description", description);
        }
        if (state != null && !state.isBlank()) {
            params.put("state", state);
        }
        return AuthorizeResult.errorRedirect(URI.create(buildRedirect(redirectUri, params)), error, description);
    }

    private String buildRedirect(String baseUri, Map<String, String> params) {
        StringBuilder sb = new StringBuilder(baseUri);
        sb.append(baseUri.contains("?") ? "&" : "?");

        boolean first = true;
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (!first) {
                sb.append("&");
            }
            first = false;
            sb.append(urlEncode(e.getKey()))
                .append("=")
                .append(urlEncode(e.getValue() == null ? "" : e.getValue()));
        }

        return sb.toString();
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private Set<String> parsePrompt(String raw) {
        if (raw == null || raw.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(raw.split("\\s+"))
            .map(String::trim)
            .filter(s -> !s.isBlank())
            .collect(Collectors.toSet());
    }
}
