package com.xerika.auth.login;

import com.xerika.auth.common.web.BearerExtractor;
import com.xerika.auth.login.dto.LoginRequest;
import com.xerika.auth.login.dto.LoginResponse;
import com.xerika.auth.login.dto.MeResponse;
import com.xerika.auth.login.dto.SessionPayload;
import com.xerika.auth.login.dto.UserPayload;
import com.xerika.auth.role.RoleRepository;
import com.xerika.auth.session.SessionService;
import com.xerika.auth.session.UserSession;
import com.xerika.auth.user.User;
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

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Path("/auth")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class LoginResource {

    @Inject
    LoginService loginService;

    @Inject
    SessionService sessionService;

    @Inject
    RoleRepository roleRepository;

    @POST
    @Path("/login")
    public Response login(LoginRequest body, @Context HttpHeaders headers) {
        String email = body == null ? null : body.email();
        String password = body == null ? null : body.password();

        Optional<User> userOpt = loginService.authenticateByEmail(email, password);
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
        List<String> roles = List.copyOf(roleRepository.findEffectiveNamesByUserId(user.id));

        return Response.ok(new LoginResponse(
            "login success",
            SessionPayload.from(session),
            UserPayload.from(user, roles)
        )).build();
    }

    @GET
    @Path("/me")
    public Response me(@Context HttpHeaders headers) {
        String token = BearerExtractor.extract(headers);
        Optional<UserSession> sessionOpt = sessionService.findActiveSession(token);

        if (sessionOpt.isEmpty()) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("message", "invalid session"))
                .build();
        }

        UserSession session = sessionOpt.get();
        List<String> roles = List.copyOf(roleRepository.findEffectiveNamesByUserId(session.user.id));

        return Response.ok(new MeResponse(
            SessionPayload.from(session),
            UserPayload.from(session.user, roles)
        )).build();
    }

    @POST
    @Path("/logout")
    public Response logout(@Context HttpHeaders headers) {
        String token = BearerExtractor.extract(headers);
        boolean ok = sessionService.logout(token);

        if (!ok) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("message", "invalid session"))
                .build();
        }

        return Response.ok(Map.of("message", "logout success")).build();
    }
}
