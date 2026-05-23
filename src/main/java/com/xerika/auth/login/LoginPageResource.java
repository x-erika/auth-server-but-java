package com.xerika.auth.login;

import com.xerika.auth.common.crypto.RandomTokens;
import com.xerika.auth.common.web.ClientIp;
import com.xerika.auth.session.SessionService;
import com.xerika.auth.session.UserSession;
import com.xerika.auth.user.User;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;
import io.vertx.ext.web.RoutingContext;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.CookieParam;
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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;

@Path("/login")
public class LoginPageResource {

    public static final String SESSION_COOKIE = "session_token";
    private static final String CSRF_COOKIE = "csrf_token";
    private static final int CSRF_TOKEN_BYTES = 24;
    private static final int CSRF_COOKIE_MAX_AGE_SECONDS = 3600;

    @Location("login.html")
    @Inject
    Template loginTemplate;

    @Inject
    LoginService loginService;

    @Inject
    SessionService sessionService;

    @ConfigProperty(name = "auth.cookie.secure", defaultValue = "false")
    boolean cookieSecure;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response renderLogin(
        @QueryParam("return_to") String returnTo,
        @QueryParam("error") String error,
        @CookieParam(CSRF_COOKIE) String existingCsrf
    ) {
        // Reuse existing CSRF cookie if the user already has one (multi-tab case).
        // Otherwise mint a fresh one and set Set-Cookie on this response.
        boolean reusable = existingCsrf != null && !existingCsrf.isBlank();
        String csrf = reusable ? existingCsrf : RandomTokens.urlSafe(CSRF_TOKEN_BYTES);

        TemplateInstance page = loginTemplate
            .data("returnTo", returnTo == null ? "" : returnTo)
            .data("email", "")
            .data("csrf", csrf)
            .data("error", normalizeError(error));

        Response.ResponseBuilder rb = Response.ok(page);
        if (!reusable) {
            rb.cookie(buildCsrfCookie(csrf, cookieSecure));
        }
        return rb.build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response submitLogin(
        @FormParam("email") String email,
        @FormParam("password") String password,
        @FormParam("return_to") String returnTo,
        @FormParam("csrf_token") String csrfForm,
        @CookieParam(CSRF_COOKIE) String csrfCookie,
        @Context HttpHeaders headers,
        @Context RoutingContext ctx
    ) {
        // Double-submit cookie check. Cookie value (HttpOnly, server-readable) must
        // match the hidden form input rendered by GET /login. A cross-origin POST
        // can't read or set the cookie, so it can't satisfy this check even if it
        // bypasses SameSite=Lax somehow.
        if (!csrfMatches(csrfForm, csrfCookie)) {
            return Response.seeOther(URI.create("/login?error=session_expired")).build();
        }

        Optional<User> userOpt = loginService.authenticate(email, password);
        if (userOpt.isEmpty()) {
            return Response.ok(
                loginTemplate
                    .data("returnTo", returnTo == null ? "" : returnTo)
                    .data("email", email == null ? "" : email)
                    .data("csrf", csrfCookie)
                    .data("error", "Invalid email or password")
                    .render()
            ).type(MediaType.TEXT_HTML).build();
        }

        User user = userOpt.get();
        String userAgent = headers.getHeaderString("User-Agent");
        String ipAddress = ClientIp.from(ctx);
        UserSession session = sessionService.createSession(user, ipAddress, userAgent);

        NewCookie cookie = new NewCookie.Builder(SESSION_COOKIE)
            .value(session.sessionToken)
            .path("/")
            .httpOnly(true)
            .secure(cookieSecure)
            .sameSite(NewCookie.SameSite.LAX)
            .maxAge(8 * 60 * 60)
            .build();

        URI target = safeRedirect(returnTo);
        return Response.seeOther(target).cookie(cookie).build();
    }

    private static String normalizeError(String error) {
        if (error == null || error.isBlank()) {
            return null;
        }
        return switch (error) {
            case "session_expired" -> "Your session expired. Please try again.";
            default -> error;
        };
    }

    private static NewCookie buildCsrfCookie(String value, boolean secure) {
        return new NewCookie.Builder(CSRF_COOKIE)
            .value(value)
            .path("/login")
            .httpOnly(true)
            .secure(secure)
            .sameSite(NewCookie.SameSite.LAX)
            .maxAge(CSRF_COOKIE_MAX_AGE_SECONDS)
            .build();
    }

    private static boolean csrfMatches(String formValue, String cookieValue) {
        if (formValue == null || cookieValue == null
            || formValue.isBlank() || cookieValue.isBlank()) {
            return false;
        }
        byte[] a = formValue.getBytes(StandardCharsets.UTF_8);
        byte[] b = cookieValue.getBytes(StandardCharsets.UTF_8);
        return a.length == b.length && MessageDigest.isEqual(a, b);
    }

    private URI safeRedirect(String returnTo) {
        if (returnTo == null || returnTo.isBlank()) {
            return URI.create("/");
        }
        if (!returnTo.startsWith("/")) {
            return URI.create("/");
        }
        // Reject protocol-relative (//evil.com) and backslash variants (/\evil.com,
        // which some browsers normalize back to //evil.com). startsWith("/") alone
        // accepts both, so check the second char explicitly.
        if (returnTo.length() > 1
            && (returnTo.charAt(1) == '/' || returnTo.charAt(1) == '\\')) {
            return URI.create("/");
        }
        try {
            URI uri = URI.create(returnTo);
            // Defense in depth: anything URI parses with a scheme/authority/host means
            // the input was an absolute URL, not a server-relative path.
            if (uri.isAbsolute() || uri.getAuthority() != null || uri.getHost() != null) {
                return URI.create("/");
            }
            return uri;
        } catch (IllegalArgumentException e) {
            return URI.create("/");
        }
    }
}
