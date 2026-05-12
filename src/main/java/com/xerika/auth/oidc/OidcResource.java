package com.xerika.auth.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.xerika.auth.common.crypto.RsaKeyProvider;
import com.xerika.auth.oauth.RequiresScope;
import com.xerika.auth.oauth.ScopeFilter;
import com.xerika.auth.oauth.Scopes;
import com.xerika.auth.oidc.dto.Jwks;
import com.xerika.auth.oidc.dto.JwksKey;
import com.xerika.auth.user.User;
import com.xerika.auth.user.UserRepository;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class OidcResource {

    @Inject
    UserRepository userRepository;

    @Inject
    RsaKeyProvider keys;

    @ConfigProperty(name = "auth.issuer.url", defaultValue = "http://localhost:8080")
    String issuerUrl;

    @GET
    @Path("/userinfo")
    @RequiresScope("openid")
    public Response userinfo(@Context ContainerRequestContext ctx) {
        JsonNode claims = (JsonNode) ctx.getProperty(ScopeFilter.CLAIMS_PROPERTY);

        String scopeRaw = claims.has("scope") ? claims.get("scope").asText("") : "";
        Set<String> scopes = Scopes.parse(scopeRaw);

        if (!claims.has("sub")) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("error", "invalid_token"))
                .build();
        }

        Optional<User> userOpt;
        try {
            userOpt = userRepository.findById(UUID.fromString(claims.get("sub").asText()));
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("error", "invalid_token"))
                .build();
        }

        if (userOpt.isEmpty() || !userOpt.get().enabled) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("error", "invalid_token"))
                .build();
        }

        User user = userOpt.get();
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("sub", user.id.toString());

        Set<String> requested = new java.util.LinkedHashSet<>();
        if (claims.has("claims_userinfo") && claims.get("claims_userinfo").isArray()) {
            for (JsonNode entry : claims.get("claims_userinfo")) {
                requested.add(entry.asText());
            }
        }

        if (scopes.contains("email") || requested.contains("email")) {
            info.put("email", user.email);
        }
        if (scopes.contains("email") || requested.contains("email_verified")) {
            info.put("email_verified", user.emailVerified);
        }

        if (scopes.contains("profile") || requested.contains("preferred_username")) {
            info.put("preferred_username", user.username);
        }
        if ((scopes.contains("profile") || requested.contains("given_name")) && user.firstName != null) {
            info.put("given_name", user.firstName);
        }
        if ((scopes.contains("profile") || requested.contains("family_name")) && user.lastName != null) {
            info.put("family_name", user.lastName);
        }
        if ((scopes.contains("profile") || requested.contains("name"))
            && user.firstName != null && user.lastName != null) {
            info.put("name", user.firstName + " " + user.lastName);
        }

        return Response.ok(info).build();
    }

    @GET
    @Path("/.well-known/openid-configuration")
    public Response discovery() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issuer", issuerUrl);
        doc.put("authorization_endpoint", issuerUrl + "/oauth/authorize");
        doc.put("token_endpoint", issuerUrl + "/oauth/token");
        doc.put("userinfo_endpoint", issuerUrl + "/userinfo");
        doc.put("revocation_endpoint", issuerUrl + "/oauth/revoke");
        doc.put("introspection_endpoint", issuerUrl + "/oauth/introspect");
        doc.put("end_session_endpoint", issuerUrl + "/oauth/logout");
        doc.put("frontchannel_logout_supported", true);
        doc.put("frontchannel_logout_session_supported", true);
        doc.put("backchannel_logout_supported", true);
        doc.put("backchannel_logout_session_supported", true);
        doc.put("request_parameter_supported", true);
        doc.put("request_uri_parameter_supported", false);
        doc.put("require_request_uri_registration", false);
        doc.put("claims_parameter_supported", true);
        doc.put("request_object_signing_alg_values_supported", List.of("HS256", "none"));
        doc.put("device_authorization_endpoint", issuerUrl + "/oauth/device-authorization");
        doc.put("jwks_uri", issuerUrl + "/.well-known/jwks.json");
        doc.put("response_types_supported", List.of("code"));
        doc.put("subject_types_supported", List.of("public"));
        doc.put("id_token_signing_alg_values_supported", List.of("RS256"));
        doc.put("scopes_supported", List.of("openid", "profile", "email"));
        doc.put("grant_types_supported", List.of(
            "authorization_code", "refresh_token", "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code"
        ));
        doc.put("token_endpoint_auth_methods_supported", List.of("client_secret_post", "none"));
        doc.put("code_challenge_methods_supported", List.of("S256", "plain"));
        doc.put("claims_supported", List.of(
            "sub", "iss", "aud", "exp", "iat", "jti", "auth_time", "nonce",
            "email", "email_verified", "preferred_username",
            "name", "given_name", "family_name", "roles"
        ));
        return Response.ok(doc).build();
    }

    @GET
    @Path("/.well-known/jwks.json")
    public Response jwks() {
        List<JwksKey> jwksKeys = new ArrayList<>();
        for (Map.Entry<String, PublicKey> entry : keys.allPublicKeys().entrySet()) {
            RSAPublicKey rsa = (RSAPublicKey) entry.getValue();
            jwksKeys.add(new JwksKey(
                "RSA",
                "sig",
                "RS256",
                entry.getKey(),
                base64UrlUnsigned(rsa.getModulus()),
                base64UrlUnsigned(rsa.getPublicExponent())
            ));
        }
        return Response.ok(new Jwks(jwksKeys)).build();
    }

    private String base64UrlUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
