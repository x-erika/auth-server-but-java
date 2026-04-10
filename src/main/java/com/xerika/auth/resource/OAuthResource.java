package com.xerika.auth.resource;

import com.xerika.auth.service.OAuthService;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.Map;

@Path("/oauth")
@Produces(MediaType.APPLICATION_JSON)
public class OAuthResource {

    @Inject
    OAuthService oauthService;

    @GET
    @Path("/authorize")
    public Response authorize(
        @QueryParam("client_id") String clientId,
        @QueryParam("redirect_uri") String redirectUri,
        @QueryParam("response_type") String responseType,
        @QueryParam("scope") String scope,
        @QueryParam("state") String state,
        @QueryParam("code_challenge") String codeChallenge,
        @QueryParam("code_challenge_method") String codeChallengeMethod,
        @Context HttpHeaders headers
    ) {
        String sessionToken = extractSessionToken(headers);

        OAuthService.AuthorizeResult result = oauthService.authorize(
            sessionToken,
            clientId,
            redirectUri,
            responseType,
            scope,
            state,
            codeChallenge,
            codeChallengeMethod
        );

        if (!result.ok()) {
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
        @FormParam("refresh_token") String refreshToken
    ) {
        OAuthService.TokenResult result = oauthService.token(
            grantType,
            code,
            redirectUri,
            clientId,
            clientSecret,
            codeVerifier,
            refreshToken
        );

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
    @Path("/revoke")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response revoke(
        @FormParam("token") String token,
        @FormParam("token_type_hint") String tokenTypeHint,
        @FormParam("client_id") String clientId,
        @FormParam("client_secret") String clientSecret
    ) {
        OAuthService.RevokeResult result = oauthService.revoke(token, tokenTypeHint, clientId, clientSecret);

        if (!result.ok()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of(
                    "error", result.error(),
                    "error_description", result.errorDescription()
                ))
                .build();
        }

        return Response.noContent().build();
    }

    private String extractSessionToken(HttpHeaders headers) {
        String bearer = headers.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7).trim();
        }
        return headers.getHeaderString("X-Session-Token");
    }
}
