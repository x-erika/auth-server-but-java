package com.xerika.auth.login;

import com.xerika.auth.common.ratelimit.RateLimitDecision;
import com.xerika.auth.common.ratelimit.RateLimiter;
import com.xerika.auth.common.redis.RedisKeys;
import com.xerika.auth.common.web.BearerExtractor;
import com.xerika.auth.common.web.ClientIp;
import io.vertx.ext.web.RoutingContext;
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
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;

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

    @Inject
    RateLimiter rateLimiter;

    @ConfigProperty(name = "auth.ratelimit.login.email.max-attempts", defaultValue = "5")
    int loginEmailMax;

    @ConfigProperty(name = "auth.ratelimit.login.email.window-seconds", defaultValue = "900")
    long loginEmailWindow;

    @ConfigProperty(name = "auth.ratelimit.login.ip.max-attempts", defaultValue = "20")
    int loginIpMax;

    @ConfigProperty(name = "auth.ratelimit.login.ip.window-seconds", defaultValue = "900")
    long loginIpWindow;

    @ConfigProperty(name = "auth.cookie.secure", defaultValue = "false")
    boolean cookieSecure;

    @POST
    @Path("/login")
    public Response login(LoginRequest body, @Context HttpHeaders headers, @Context RoutingContext ctx) {
        String identifier = body == null ? null : body.resolveIdentifier();
        String password = body == null ? null : body.password();
        String ipAddress = ClientIp.from(ctx);

        if (identifier != null && !identifier.isBlank()) {
            RateLimitDecision d = rateLimiter.check(
                RedisKeys.rlLoginEmail(identifier.trim().toLowerCase()),
                loginEmailMax, loginEmailWindow);
            if (!d.allowed()) {
                return RateLimiter.tooManyRequests(d);
            }
        }
        if (ipAddress != null && !ipAddress.isBlank()) {
            RateLimitDecision d = rateLimiter.check(
                RedisKeys.rlLoginIp(ipAddress),
                loginIpMax, loginIpWindow);
            if (!d.allowed()) {
                return RateLimiter.tooManyRequests(d);
            }
        }

        Optional<User> userOpt = loginService.authenticate(identifier, password);
        if (userOpt.isEmpty()) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("message", "invalid credentials"))
                .build();
        }

        // Per-account failure bucket resets on successful auth so a user who
        // genuinely logs in 5+ times in a window does not lock themselves out.
        // We keep the per-IP bucket counting up regardless — that one defends
        // against horizontal abuse (one IP, many target accounts) where a
        // single victim's success shouldn't refund the attacker's quota.
        if (identifier != null && !identifier.isBlank()) {
            rateLimiter.reset(RedisKeys.rlLoginEmail(identifier.trim().toLowerCase()));
        }

        User user = userOpt.get();
        String userAgent = headers.getHeaderString("User-Agent");
        UserSession session = sessionService.createSession(user, ipAddress, userAgent);
        List<String> roles = List.copyOf(roleRepository.findEffectiveNamesByUserId(user.id));

        // Also set the session cookie so the SPA can hand the browser off to
        // /oauth/authorize as a top-level navigation without having to embed the
        // token in the URL. SameSite=Lax is enough because /oauth/authorize is
        // hit via a full-page redirect, not a cross-site subresource.
        NewCookie cookie = new NewCookie.Builder(BearerExtractor.SESSION_COOKIE)
            .value(session.sessionToken)
            .path("/")
            .httpOnly(true)
            .secure(cookieSecure)
            .sameSite(NewCookie.SameSite.LAX)
            .maxAge(8 * 60 * 60)
            .build();

        return Response.ok(new LoginResponse(
            "login success",
            SessionPayload.from(session),
            UserPayload.from(user, roles)
        )).cookie(cookie).build();
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

        NewCookie clear = new NewCookie.Builder(BearerExtractor.SESSION_COOKIE)
            .value("")
            .path("/")
            .httpOnly(true)
            .secure(cookieSecure)
            .sameSite(NewCookie.SameSite.LAX)
            .maxAge(0)
            .build();

        return Response.ok(Map.of("message", "logout success")).cookie(clear).build();
    }
}
