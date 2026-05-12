package com.xerika.auth.oauth.authorize;

import com.fasterxml.jackson.databind.JsonNode;
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

    @Inject
    RequestObjectParser requestObjectParser;

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
        String requestJwt,
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
        if (session == null || promptLogin) {
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

        if (requestJwt != null && !requestJwt.isBlank()) {
            JsonNode requestPayload = requestObjectParser.parse(requestJwt, client).orElse(null);
            if (requestPayload == null) {
                return AuthorizeResult.error("invalid_request_object", "Could not validate request JWT");
            }
            redirectUri = overrideString(redirectUri, requestPayload, "redirect_uri");
            scope = overrideString(scope, requestPayload, "scope");
            state = overrideString(state, requestPayload, "state");
            nonce = overrideString(nonce, requestPayload, "nonce");
            codeChallenge = overrideString(codeChallenge, requestPayload, "code_challenge");
            codeChallengeMethod = overrideString(codeChallengeMethod, requestPayload, "code_challenge_method");
            if (requestPayload.has("claims") && !requestPayload.get("claims").isNull()) {
                claimsJson = requestPayload.get("claims").toString();
            }
        }

        if (!clientRepository.isRedirectUriAllowed(client.id, redirectUri)) {
            return AuthorizeResult.error("invalid_request", "redirect_uri is not registered");
        }

        if (!Scopes.isSubsetOf(scope, client.scopes)) {
            return AuthorizeResult.error("invalid_scope", "Requested scope is not allowed for this client");
        }

        String resolvedMethod = codeChallengeMethod;
        if (client.pkceRequired) {
            if (codeChallenge == null || codeChallenge.isBlank()) {
                return AuthorizeResult.error("invalid_request", "code_challenge is required");
            }
            resolvedMethod = (codeChallengeMethod == null || codeChallengeMethod.isBlank())
                ? "plain"
                : codeChallengeMethod;
            if (!pkceVerifier.isMethodSupported(resolvedMethod)) {
                return AuthorizeResult.error("invalid_request", "Unsupported code_challenge_method");
            }
        }

        boolean hasConsent = !promptConsent && consentService.hasConsent(session.user.id, client.id, scope);
        if (!hasConsent) {
            if (promptNone) {
                return AuthorizeResult.error("consent_required", "Consent is required but prompt=none was specified");
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
        authCodeStore.cleanupExpired();

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

    private String overrideString(String original, JsonNode payload, String field) {
        if (payload.has(field) && !payload.get(field).isNull()) {
            String value = payload.get(field).asText();
            if (!value.isBlank()) {
                return value;
            }
        }
        return original;
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
