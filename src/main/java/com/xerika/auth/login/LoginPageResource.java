package com.xerika.auth.login;

import com.xerika.auth.session.SessionService;
import com.xerika.auth.session.UserSession;
import com.xerika.auth.user.User;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
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
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;

import java.net.URI;
import java.util.Optional;

@Path("/login")
public class LoginPageResource {

    public static final String SESSION_COOKIE = "session_token";

    @Location("login.html")
    @Inject
    Template loginTemplate;

    @Inject
    LoginService loginService;

    @Inject
    SessionService sessionService;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public TemplateInstance renderLogin(
        @QueryParam("return_to") String returnTo,
        @QueryParam("error") String error
    ) {
        return loginTemplate
            .data("returnTo", returnTo == null ? "" : returnTo)
            .data("email", "")
            .data("error", error == null || error.isBlank() ? null : error);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response submitLogin(
        @FormParam("email") String email,
        @FormParam("password") String password,
        @FormParam("return_to") String returnTo,
        @Context HttpHeaders headers
    ) {
        Optional<User> userOpt = loginService.authenticateByEmail(email, password);
        if (userOpt.isEmpty()) {
            return Response.ok(
                loginTemplate
                    .data("returnTo", returnTo == null ? "" : returnTo)
                    .data("email", email == null ? "" : email)
                    .data("error", "Invalid email or password")
                    .render()
            ).type(MediaType.TEXT_HTML).build();
        }

        User user = userOpt.get();
        String userAgent = headers.getHeaderString("User-Agent");
        String xForwardedFor = headers.getHeaderString("X-Forwarded-For");
        String ipAddress = xForwardedFor == null ? null : xForwardedFor.split(",")[0].trim();
        UserSession session = sessionService.createSession(user, ipAddress, userAgent);

        NewCookie cookie = new NewCookie.Builder(SESSION_COOKIE)
            .value(session.sessionToken)
            .path("/")
            .httpOnly(true)
            .sameSite(NewCookie.SameSite.LAX)
            .maxAge(8 * 60 * 60)
            .build();

        URI target = safeRedirect(returnTo);
        return Response.seeOther(target).cookie(cookie).build();
    }

    private URI safeRedirect(String returnTo) {
        if (returnTo == null || returnTo.isBlank()) {
            return URI.create("/");
        }
        if (!returnTo.startsWith("/")) {
            return URI.create("/");
        }
        return URI.create(returnTo);
    }
}
