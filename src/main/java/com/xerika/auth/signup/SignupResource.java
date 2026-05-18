package com.xerika.auth.signup;

import com.xerika.auth.common.ratelimit.RateLimitDecision;
import com.xerika.auth.common.ratelimit.RateLimiter;
import com.xerika.auth.common.redis.RedisKeys;
import com.xerika.auth.signup.dto.SignupRequest;
import com.xerika.auth.signup.dto.SignupResult;
import com.xerika.auth.signup.dto.VerifyEmailResult;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.util.Map;

@Path("/auth")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class SignupResource {

    @Inject
    SignupFlow signupFlow;

    @Inject
    RateLimiter rateLimiter;

    @ConfigProperty(name = "auth.ratelimit.signup.ip.max-attempts", defaultValue = "3")
    int signupIpMax;

    @ConfigProperty(name = "auth.ratelimit.signup.ip.window-seconds", defaultValue = "3600")
    long signupIpWindow;

    @ConfigProperty(name = "auth.ratelimit.verify-email.ip.max-attempts", defaultValue = "10")
    int verifyEmailIpMax;

    @ConfigProperty(name = "auth.ratelimit.verify-email.ip.window-seconds", defaultValue = "60")
    long verifyEmailIpWindow;

    @POST
    @Path("/signup")
    public Response signup(SignupRequest body, @Context HttpHeaders headers) {
        String ip = clientIp(headers);
        if (ip != null && !ip.isBlank()) {
            RateLimitDecision d = rateLimiter.check(
                RedisKeys.rlSignupIp(ip), signupIpMax, signupIpWindow);
            if (!d.allowed()) {
                return RateLimiter.tooManyRequests(d);
            }
        }

        SignupResult result = signupFlow.signup(body);

        if (!result.ok()) {
            Response.Status status = "conflict".equals(result.error())
                ? Response.Status.CONFLICT
                : Response.Status.BAD_REQUEST;
            return Response.status(status)
                .entity(Map.of(
                    "error", result.error(),
                    "error_description", result.errorDescription()
                ))
                .build();
        }

        return Response.status(Response.Status.CREATED)
            .entity(Map.of(
                "message", "signup successful, verify your email",
                "userId", result.userId(),
                "verificationToken", result.verificationToken()
            ))
            .build();
    }

    @POST
    @Path("/verify-email")
    public Response verifyEmail(Map<String, String> body, @Context HttpHeaders headers) {
        String ip = clientIp(headers);
        if (ip != null && !ip.isBlank()) {
            RateLimitDecision d = rateLimiter.check(
                RedisKeys.rlVerifyEmail(ip), verifyEmailIpMax, verifyEmailIpWindow);
            if (!d.allowed()) {
                return RateLimiter.tooManyRequests(d);
            }
        }

        String token = body == null ? null : body.get("token");
        VerifyEmailResult result = signupFlow.verifyEmail(token);

        if (!result.ok()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of(
                    "error", result.error(),
                    "error_description", result.errorDescription()
                ))
                .build();
        }

        return Response.ok(Map.of(
            "message", "email verified",
            "userId", result.userId()
        )).build();
    }

    private static String clientIp(HttpHeaders headers) {
        String xff = headers.getHeaderString("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return null;
    }
}
