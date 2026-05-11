package com.xerika.auth.signup;

import com.xerika.auth.signup.dto.SignupRequest;
import com.xerika.auth.signup.dto.SignupResult;
import com.xerika.auth.signup.dto.VerifyEmailResult;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.Map;

@Path("/auth")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class SignupResource {

    @Inject
    SignupFlow signupFlow;

    @POST
    @Path("/signup")
    public Response signup(SignupRequest body) {
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
    public Response verifyEmail(Map<String, String> body) {
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
}
