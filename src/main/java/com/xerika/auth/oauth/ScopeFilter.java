package com.xerika.auth.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.xerika.auth.common.crypto.JwtValidator;
import com.xerika.auth.common.web.BearerExtractor;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Provider
public class ScopeFilter implements ContainerRequestFilter {

    public static final String CLAIMS_PROPERTY = "jwt.claims";

    @Context
    ResourceInfo resourceInfo;

    @Inject
    JwtValidator jwtValidator;

    @Override
    public void filter(ContainerRequestContext ctx) {
        Method method = resourceInfo.getResourceMethod();
        if (method == null) {
            return;
        }

        RequiresScope requirement = method.getAnnotation(RequiresScope.class);
        if (requirement == null) {
            requirement = method.getDeclaringClass().getAnnotation(RequiresScope.class);
        }
        if (requirement == null) {
            return;
        }

        String[] required = requirement.value();
        if (required == null || required.length == 0) {
            return;
        }

        String token = BearerExtractor.extract(ctx);
        Optional<JsonNode> claimsOpt = jwtValidator.validate(token);
        if (claimsOpt.isEmpty()) {
            ctx.abortWith(Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("error", "invalid_token"))
                .build());
            return;
        }

        JsonNode claims = claimsOpt.get();
        String scopeRaw = claims.has("scope") ? claims.get("scope").asText("") : "";
        Set<String> scopes = Scopes.parse(scopeRaw);

        boolean granted = false;
        for (String s : required) {
            if (scopes.contains(s)) {
                granted = true;
                break;
            }
        }

        if (!granted) {
            ctx.abortWith(Response.status(Response.Status.FORBIDDEN)
                .entity(Map.of(
                    "error", "insufficient_scope",
                    "required_scopes", List.of(required)
                ))
                .build());
            return;
        }

        ctx.setProperty(CLAIMS_PROPERTY, claims);
    }
}
