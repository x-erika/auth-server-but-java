package com.xerika.auth.oauth.consent;

import com.xerika.auth.client.Client;
import com.xerika.auth.client.ClientRepository;
import com.xerika.auth.common.web.BearerExtractor;
import com.xerika.auth.oauth.Scopes;
import com.xerika.auth.oauth.authorize.AuthorizeFlow;
import com.xerika.auth.oauth.authorize.AuthorizeResult;
import com.xerika.auth.session.SessionService;
import com.xerika.auth.session.UserSession;
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
import jakarta.ws.rs.core.Response;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Path("/consent")
public class ConsentResource {

    @Inject
    PendingAuthorizationStore pendingStore;

    @Inject
    SessionService sessionService;

    @Inject
    ClientRepository clientRepository;

    @Inject
    AuthorizeFlow authorizeFlow;

    @Inject
    Template consent;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response render(
        @QueryParam("req") String requestId,
        @Context HttpHeaders headers
    ) {
        String token = BearerExtractor.extract(headers);
        Optional<UserSession> sessionOpt = sessionService.findActiveSession(token);
        if (sessionOpt.isEmpty()) {
            return Response.seeOther(URI.create("/login")).build();
        }

        Optional<PendingAuthorization> pendingOpt = pendingStore.get(requestId);
        if (pendingOpt.isEmpty()) {
            TemplateInstance page = consent.data("error", "Consent request not found or expired.");
            return Response.ok(page).build();
        }

        PendingAuthorization pending = pendingOpt.get();
        if (!sessionOpt.get().id.equals(pending.sessionId)) {
            return Response.status(Response.Status.FORBIDDEN)
                .entity("session mismatch")
                .build();
        }

        Optional<Client> clientOpt = clientRepository.findByClientId(pending.clientId);
        String clientName = clientOpt.map(c -> c.name != null && !c.name.isBlank() ? c.name : c.clientId)
            .orElse(pending.clientId);

        Set<String> scopes = Scopes.parse(pending.scope);

        TemplateInstance page = consent
            .data("requestId", pending.requestId)
            .data("clientName", clientName)
            .data("clientId", pending.clientId)
            .data("scopes", List.copyOf(scopes))
            .data("error", null);

        return Response.ok(page).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response submit(
        @FormParam("req") String requestId,
        @FormParam("action") String action,
        @Context HttpHeaders headers
    ) {
        String token = BearerExtractor.extract(headers);
        Optional<UserSession> sessionOpt = sessionService.findActiveSession(token);
        if (sessionOpt.isEmpty()) {
            return Response.seeOther(URI.create("/login")).build();
        }

        Optional<PendingAuthorization> pendingOpt = pendingStore.take(requestId);
        if (pendingOpt.isEmpty()) {
            TemplateInstance page = consent.data("error", "Consent request not found or expired.");
            return Response.ok(page).type(MediaType.TEXT_HTML_TYPE).build();
        }

        PendingAuthorization pending = pendingOpt.get();
        if (!sessionOpt.get().id.equals(pending.sessionId)) {
            return Response.status(Response.Status.FORBIDDEN)
                .entity("session mismatch")
                .build();
        }

        if (!"allow".equalsIgnoreCase(action)) {
            String location = pending.redirectUri
                + (pending.redirectUri.contains("?") ? "&" : "?")
                + "error=access_denied&error_description="
                + URLEncoder.encode("user denied consent", StandardCharsets.UTF_8);
            if (pending.state != null && !pending.state.isBlank()) {
                location += "&state=" + URLEncoder.encode(pending.state, StandardCharsets.UTF_8);
            }
            return Response.seeOther(URI.create(location)).build();
        }

        AuthorizeResult result = authorizeFlow.completeAfterConsent(pending);
        if (!result.ok()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(result.error() + ": " + result.errorDescription())
                .type(MediaType.TEXT_PLAIN)
                .build();
        }

        return Response.seeOther(result.redirect()).build();
    }
}
