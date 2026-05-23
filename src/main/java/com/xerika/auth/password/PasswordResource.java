package com.xerika.auth.password;

import com.xerika.auth.common.web.BearerExtractor;
import com.xerika.auth.session.SessionService;
import com.xerika.auth.session.UserSession;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
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
public class PasswordResource {

    @Inject
    PasswordFlow passwordFlow;

    @Inject
    SessionService sessionService;

    @POST
    @Path("/forgot-password")
    public Response forgotPassword(Map<String, String> body) {
        String identifier = body == null
            ? null
            : firstNonBlank(body.get("identifier"), body.get("email"), body.get("nim"), body.get("nip"));

        Optional<String> tokenOpt = passwordFlow.requestReset(identifier);

        // Always respond identically to prevent account enumeration. In dev,
        // the response also includes the token for testing — in prod this
        // branch should be removed and the token only delivered via email.
        Map<String, Object> payload = new HashMap<>();
        payload.put("message", "if the account exists, a reset token has been issued");
        tokenOpt.ifPresent(token -> payload.put("resetToken", token));
        return Response.ok(payload).build();
    }

    @POST
    @Path("/reset-password")
    public Response resetPassword(Map<String, String> body) {
        String token = body == null ? null : body.get("token");
        String newPassword = body == null
            ? null
            : firstNonBlank(body.get("newPassword"), body.get("new_password"), body.get("password"));

        Optional<PasswordFlow.ResetError> err = passwordFlow.consumeReset(token, newPassword);
        if (err.isPresent()) {
            String code = switch (err.get()) {
                case INVALID_TOKEN -> "invalid_token";
                case WEAK_PASSWORD -> "weak_password";
            };
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("error", code))
                .build();
        }
        return Response.ok(Map.of("message", "password updated")).build();
    }

    @PUT
    @Path("/change-password")
    public Response changePassword(Map<String, String> body, @Context HttpHeaders headers) {
        String token = BearerExtractor.extract(headers);
        Optional<UserSession> sessionOpt = sessionService.findActiveSession(token);
        if (sessionOpt.isEmpty()) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("message", "invalid session"))
                .build();
        }

        String oldPassword = body == null
            ? null
            : firstNonBlank(body.get("oldPassword"), body.get("currentPassword"), body.get("old_password"));
        String newPassword = body == null
            ? null
            : firstNonBlank(body.get("newPassword"), body.get("new_password"));

        Optional<PasswordFlow.ChangeError> err =
            passwordFlow.changePassword(sessionOpt.get().user.id, oldPassword, newPassword);
        if (err.isPresent()) {
            String code = switch (err.get()) {
                case WRONG_PASSWORD -> "wrong_password";
                case WEAK_PASSWORD -> "weak_password";
            };
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("error", code))
                .build();
        }
        return Response.ok(Map.of("message", "password changed")).build();
    }

    private static String firstNonBlank(String... values) {
        if (values == null) return null;
        for (String v : values) {
            if (v != null && !v.isBlank()) return v;
        }
        return null;
    }
}
