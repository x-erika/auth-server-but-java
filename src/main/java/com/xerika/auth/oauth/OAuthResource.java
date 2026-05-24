package com.xerika.auth.oauth;

import com.xerika.auth.common.ratelimit.RateLimitDecision;
import com.xerika.auth.common.ratelimit.RateLimiter;
import com.xerika.auth.common.redis.RedisKeys;
import com.xerika.auth.common.web.BearerExtractor;
import com.xerika.auth.oauth.authorize.AuthorizeFlow;
import com.xerika.auth.oauth.authorize.AuthorizeResult;
import com.xerika.auth.oauth.device.DeviceAuthorizationResult;
import com.xerika.auth.oauth.device.DeviceFlow;
import com.xerika.auth.oauth.device.DeviceVerifyResult;
import com.xerika.auth.oauth.logout.LogoutFlow;
import com.xerika.auth.oauth.logout.LogoutResult;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import com.xerika.auth.oauth.token.IntrospectFlow;
import com.xerika.auth.oauth.token.IntrospectResult;
import com.xerika.auth.oauth.token.RevokeFlow;
import com.xerika.auth.oauth.token.RevokeResult;
import com.xerika.auth.oauth.token.TokenFlow;
import com.xerika.auth.oauth.token.TokenResult;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Path("/oauth")
@Produces(MediaType.APPLICATION_JSON)
public class OAuthResource {

    @Inject
    AuthorizeFlow authorizeFlow;

    @Inject
    TokenFlow tokenFlow;

    @Inject
    RevokeFlow revokeFlow;

    @Inject
    IntrospectFlow introspectFlow;

    @Inject
    LogoutFlow logoutFlow;

    @Inject
    DeviceFlow deviceFlow;

    @Inject
    Template logout;

    @Inject
    RateLimiter rateLimiter;

    @ConfigProperty(name = "auth.ratelimit.device-auth.client.max-attempts", defaultValue = "10")
    int deviceAuthClientMax;

    @ConfigProperty(name = "auth.ratelimit.device-auth.client.window-seconds", defaultValue = "60")
    long deviceAuthClientWindow;

    @GET
    @Path("/authorize")
    public Response authorize(
        @QueryParam("client_id") String clientId,
        @QueryParam("redirect_uri") String redirectUri,
        @QueryParam("response_type") String responseType,
        @QueryParam("scope") String scope,
        @QueryParam("state") String state,
        @QueryParam("nonce") String nonce,
        @QueryParam("prompt") String prompt,
        @QueryParam("max_age") Long maxAge,
        @QueryParam("code_challenge") String codeChallenge,
        @QueryParam("code_challenge_method") String codeChallengeMethod,
        @QueryParam("claims") String claimsJson,
        @Context HttpHeaders headers,
        @Context UriInfo uriInfo
    ) {
        String sessionToken = BearerExtractor.extract(headers);

        AuthorizeResult result = authorizeFlow.authorize(
            sessionToken,
            clientId,
            redirectUri,
            responseType,
            scope,
            state,
            nonce,
            prompt,
            maxAge,
            codeChallenge,
            codeChallengeMethod,
            claimsJson
        );

        if (!result.ok()) {
            if ("invalid_session".equals(result.error())) {
                String returnTo = uriInfo.getRequestUri().getRawPath()
                    + (uriInfo.getRequestUri().getRawQuery() == null
                        ? ""
                        : "?" + uriInfo.getRequestUri().getRawQuery());
                String location = "/login?return_to="
                    + URLEncoder.encode(returnTo, StandardCharsets.UTF_8);
                return Response.seeOther(URI.create(location)).build();
            }
            if ("consent_required".equals(result.error()) && result.consentRequestId() != null) {
                String location = "/consent?req="
                    + URLEncoder.encode(result.consentRequestId(), StandardCharsets.UTF_8);
                return Response.seeOther(URI.create(location)).build();
            }
            // RFC 6749 §4.1.2.1 error-redirect path: AuthorizeFlow has validated the
            // redirect URI against the client's registered list before building this.
            if (result.redirect() != null) {
                return Response.seeOther(result.redirect()).build();
            }
            // Fallback (pre-validation errors): redirect URI not trusted yet, so
            // we keep the JSON 400 to avoid bouncing the user to an unknown URI.
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of(
                    "error", result.error(),
                    "error_description", result.errorDescription()
                ))
                .build();
        }

        return Response.seeOther(result.redirect()).build();
    }

    @POST
    @Path("/token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response token(
        @FormParam("grant_type") String grantType,
        @FormParam("code") String code,
        @FormParam("redirect_uri") String redirectUri,
        @FormParam("client_id") String clientId,
        @FormParam("client_secret") String clientSecret,
        @FormParam("code_verifier") String codeVerifier,
        @FormParam("refresh_token") String refreshToken,
        @FormParam("scope") String scope,
        @FormParam("device_code") String deviceCode
    ) {
        TokenResult result = tokenFlow.token(
            grantType,
            code,
            redirectUri,
            clientId,
            clientSecret,
            codeVerifier,
            refreshToken,
            scope,
            deviceCode
        );

        if (!result.ok()) {
            return oauthErrorResponse(result.error(), result.errorDescription());
        }

        return Response.ok(result.payload()).build();
    }

    @POST
    @Path("/revoke")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response revoke(
        @FormParam("token") String token,
        @FormParam("token_type_hint") String tokenTypeHint,
        @FormParam("client_id") String clientId,
        @FormParam("client_secret") String clientSecret
    ) {
        RevokeResult result = revokeFlow.revoke(token, tokenTypeHint, clientId, clientSecret);

        if (!result.ok()) {
            return oauthErrorResponse(result.error(), result.errorDescription());
        }

        // RFC 7009 §2.2 prescribes 200 OK on successful revocation (including the
        // "invalid token" case, which RevokeFlow already collapses into ok=true).
        return Response.ok().build();
    }

    @POST
    @Path("/introspect")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response introspect(
        @FormParam("token") String token,
        @FormParam("token_type_hint") String tokenTypeHint,
        @FormParam("client_id") String clientId,
        @FormParam("client_secret") String clientSecret
    ) {
        IntrospectResult result = introspectFlow.introspect(token, clientId, clientSecret);

        if (!result.ok()) {
            return oauthErrorResponse(result.error(), result.errorDescription());
        }

        return Response.ok(result.payload()).build();
    }

    // RFC 6749 §5.2 — invalid_client gets 401 (with WWW-Authenticate when HTTP
    // Basic was used, which we don't accept — client_secret_post only); other
    // errors get 400. Centralised so /token, /revoke, /introspect stay consistent.
    private static Response oauthErrorResponse(String error, String description) {
        Response.Status status = "invalid_client".equals(error)
            ? Response.Status.UNAUTHORIZED
            : Response.Status.BAD_REQUEST;
        return Response.status(status)
            .entity(Map.of(
                "error", error,
                "error_description", description == null ? "" : description
            ))
            .build();
    }

    @GET
    @Path("/logout")
    public Response logout(
        @QueryParam("id_token_hint") String idTokenHint,
        @QueryParam("post_logout_redirect_uri") String postLogoutRedirectUri,
        @QueryParam("state") String state,
        @Context HttpHeaders headers
    ) {
        String sessionToken = BearerExtractor.extract(headers);
        LogoutResult result = logoutFlow.logout(idTokenHint, sessionToken, postLogoutRedirectUri);

        String finalRedirect = null;
        // Only honour the redirect after LogoutFlow validated it against the requester
        // client's registered URIs — closes the open-redirect hole on /oauth/logout.
        if (result.validatedPostLogoutRedirectUri() != null) {
            finalRedirect = result.validatedPostLogoutRedirectUri();
            if (state != null && !state.isBlank()) {
                String sep = finalRedirect.contains("?") ? "&" : "?";
                finalRedirect = finalRedirect + sep + "state="
                    + URLEncoder.encode(state, StandardCharsets.UTF_8);
            }
        }

        if (!result.frontchannelLogoutUris().isEmpty()) {
            TemplateInstance page = logout
                .data("frontchannelUris", result.frontchannelLogoutUris())
                .data("finalRedirect", finalRedirect);
            return Response.ok(page).type(MediaType.TEXT_HTML_TYPE).build();
        }

        if (finalRedirect != null) {
            return Response.seeOther(URI.create(finalRedirect)).build();
        }

        return Response.ok(Map.of(
            "message", result.terminated() ? "logged out" : "no active session"
        )).build();
    }

    @POST
    @Path("/device-authorization")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response deviceAuthorization(
        @FormParam("client_id") String clientId,
        @FormParam("scope") String scope
    ) {
        if (clientId != null && !clientId.isBlank()) {
            RateLimitDecision d = rateLimiter.check(
                RedisKeys.rlDeviceAuth(clientId.trim()),
                deviceAuthClientMax, deviceAuthClientWindow);
            if (!d.allowed()) {
                return RateLimiter.tooManyRequests(d);
            }
        }
        DeviceAuthorizationResult result = deviceFlow.requestDeviceAuthorization(clientId, scope);

        if (!result.ok()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of(
                    "error", result.error(),
                    "error_description", result.errorDescription()
                ))
                .build();
        }

        return Response.ok(result.payload()).build();
    }

    @POST
    @Path("/device/verify")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response deviceVerify(
        @FormParam("user_code") String userCode,
        @FormParam("action") String action,
        @Context HttpHeaders headers
    ) {
        String sessionToken = BearerExtractor.extract(headers);
        boolean approve = !"deny".equalsIgnoreCase(action);

        DeviceVerifyResult result = deviceFlow.verifyUserCode(userCode, sessionToken, approve);

        if (!result.ok()) {
            Response.Status status = "invalid_session".equals(result.error())
                ? Response.Status.UNAUTHORIZED
                : Response.Status.BAD_REQUEST;
            return Response.status(status)
                .entity(Map.of(
                    "error", result.error(),
                    "error_description", result.errorDescription()
                ))
                .build();
        }

        return Response.ok(Map.of(
            "message", approve ? "device authorized" : "device denied"
        )).build();
    }
}
