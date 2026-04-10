package com.xerika.auth.resource;

import com.xerika.auth.entity.User;
import com.xerika.auth.entity.UserSession;
import com.xerika.auth.service.AuthService;
import com.xerika.auth.service.SessionService;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Path("/auth")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class AuthResource {

    @Inject
    AuthService authService;

    @Inject
    SessionService sessionService;

    @POST
    @Path("/login")
    public Response login(Map<String, String> body, @Context HttpHeaders headers) {
        String email = body.getOrDefault("email", "");
        String password = body.getOrDefault("password", "");

        Optional<User> userOpt = authService.authenticateByEmail(email, password);
        if (userOpt.isEmpty()) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("message", "invalid credentials"))
                .build();
        }

        User user = userOpt.get();
        String userAgent = headers.getHeaderString("User-Agent");
        String xForwardedFor = headers.getHeaderString("X-Forwarded-For");
        String ipAddress = xForwardedFor == null ? null : xForwardedFor.split(",")[0].trim();

        UserSession session = sessionService.createSession(user, ipAddress, userAgent);

        return Response.ok(Map.of(
            "message", "login success",
            "session", Map.of(
                "sessionToken", session.sessionToken,
                "expiresAt", session.expiresAt.toString()
            ),
            "user", userPayload(user)
        )).build();
    }

    @GET
    @Path("/me")
    public Response me(@Context HttpHeaders headers) {
        String token = extractSessionToken(headers);
        Optional<UserSession> sessionOpt = sessionService.findActiveSession(token);

        if (sessionOpt.isEmpty()) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("message", "invalid session"))
                .build();
        }

        UserSession session = sessionOpt.get();
        return Response.ok(Map.of(
            "session", sessionPayload(session),
            "user", userPayload(session.user)
        )).build();
    }

    @POST
    @Path("/logout")
    public Response logout(@Context HttpHeaders headers) {
        String token = extractSessionToken(headers);
        boolean ok = sessionService.logout(token);

        if (!ok) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("message", "invalid session"))
                .build();
        }

        return Response.ok(Map.of("message", "logout success")).build();
    }

    private String extractSessionToken(HttpHeaders headers) {
        String bearer = headers.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7).trim();
        }
        return headers.getHeaderString("X-Session-Token");
    }

    private Map<String, Object> userPayload(User user) {
        return Map.of(
            "id", user.id.toString(),
            "email", user.email,
            "username", user.username,
            "emailVerified", user.emailVerified
        );
    }

    private Map<String, Object> sessionPayload(UserSession session) {
        Map<String, Object> out = new HashMap<>();
        out.put("sessionToken", session.sessionToken);
        out.put("expiresAt", session.expiresAt == null ? null : session.expiresAt.toString());
        out.put("lastAccessedAt", session.lastAccessedAt == null ? null : session.lastAccessedAt.toString());
        return out;
    }
}
