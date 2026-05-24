package com.xerika.auth.admin;

import com.xerika.auth.admin.dto.ClientRequest;
import com.xerika.auth.admin.dto.ClientSummary;
import com.xerika.auth.admin.dto.ConsentSummary;
import com.xerika.auth.admin.dto.RoleSummary;
import com.xerika.auth.admin.dto.SessionSummary;
import com.xerika.auth.admin.dto.UserCreateRequest;
import com.xerika.auth.admin.dto.UserSummary;
import com.xerika.auth.admin.dto.UserUpdateRequest;
import com.xerika.auth.client.Client;
import com.xerika.auth.client.ClientRepository;
import com.xerika.auth.client.ClientSecretHasher;
import com.xerika.auth.client.RedirectUri;
import com.xerika.auth.common.crypto.Argon2Hasher;
import com.xerika.auth.common.crypto.RsaKeyProvider;
import com.xerika.auth.common.web.BearerExtractor;
import com.xerika.auth.oauth.consent.UserConsent;
import com.xerika.auth.oauth.consent.UserConsentRepository;
import com.xerika.auth.oauth.token.RefreshTokenRepository;
import com.xerika.auth.role.RequiresRole;
import com.xerika.auth.role.Role;
import com.xerika.auth.role.RoleRepository;
import com.xerika.auth.session.SessionRepository;
import com.xerika.auth.session.SessionService;
import com.xerika.auth.session.UserSession;
import com.xerika.auth.user.Credential;
import com.xerika.auth.user.CredentialRepository;
import com.xerika.auth.user.User;
import com.xerika.auth.user.UserRepository;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Path("/admin")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@RequiresRole("admin")
public class AdminResource {

    private static final Logger LOG = Logger.getLogger(AdminResource.class);

    @Inject
    SessionService sessionService;

    @Inject
    UserRepository userRepository;

    @Inject
    RoleRepository roleRepository;

    @Inject
    RsaKeyProvider rsaKeyProvider;

    @Inject
    ClientRepository clientRepository;

    @Inject
    SessionRepository sessionRepository;

    @Inject
    RefreshTokenRepository refreshTokenRepository;

    @Inject
    UserConsentRepository userConsentRepository;

    @Inject
    CredentialRepository credentialRepository;

    @GET
    @Path("/ping")
    public Response ping(@Context HttpHeaders headers) {
        UserSession session = sessionService
            .findActiveSession(BearerExtractor.extract(headers))
            .orElseThrow();

        return Response.ok(Map.of(
            "message", "hello admin",
            "username", session.user.username
        )).build();
    }

    @GET
    @Path("/roles")
    public Response listRoles() {
        List<RoleSummary> roles = roleRepository.findAll().stream()
            .map(RoleSummary::from)
            .toList();
        return Response.ok(roles).build();
    }

    @GET
    @Path("/users")
    public Response listUsers() {
        List<UserSummary> users = userRepository.findAll(100).stream()
            .map(u -> UserSummary.from(u, roleRepository.findNamesByUserId(u.id)))
            .toList();
        return Response.ok(users).build();
    }

    @POST
    @Path("/users/{userId}/roles/{roleName}")
    public Response assignRole(
        @PathParam("userId") String userIdStr,
        @PathParam("roleName") String roleName
    ) {
        UUID userId;
        try {
            userId = UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid userId")).build();
        }

        Optional<User> userOpt = userRepository.findById(userId);
        Optional<Role> roleOpt = roleRepository.findByName(roleName);
        if (userOpt.isEmpty() || roleOpt.isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(Map.of("message", "user or role not found")).build();
        }

        Role role = roleOpt.get();
        if (!roleRepository.isAssigned(userId, role.id)) {
            roleRepository.assignToUser(userId, role.id);
        }

        return Response.ok(Map.of(
            "message", "role assigned",
            "roles", roleRepository.findNamesByUserId(userId)
        )).build();
    }

    @DELETE
    @Path("/users/{userId}/roles/{roleName}")
    public Response revokeRole(
        @PathParam("userId") String userIdStr,
        @PathParam("roleName") String roleName
    ) {
        UUID userId;
        try {
            userId = UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid userId")).build();
        }

        Optional<Role> roleOpt = roleRepository.findByName(roleName);
        if (roleOpt.isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(Map.of("message", "role not found")).build();
        }

        roleRepository.unassignFromUser(userId, roleOpt.get().id);

        return Response.ok(Map.of(
            "message", "role revoked",
            "roles", roleRepository.findNamesByUserId(userId)
        )).build();
    }

    @POST
    @Path("/roles/{childName}/parent/{parentName}")
    public Response setRoleParent(
        @PathParam("childName") String childName,
        @PathParam("parentName") String parentName
    ) {
        Optional<Role> childOpt = roleRepository.findByName(childName);
        Optional<Role> parentOpt = roleRepository.findByName(parentName);
        if (childOpt.isEmpty() || parentOpt.isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(Map.of("message", "role not found")).build();
        }

        Role child = childOpt.get();
        Role parent = parentOpt.get();
        // Cycle + self-parent checks now live in the repo (transactional + locked),
        // so they hold under concurrent setParent calls.
        try {
            roleRepository.setParent(child.id, parent.id);
        } catch (RoleRepository.RoleCycleException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", e.getMessage())).build();
        }
        return Response.ok(Map.of(
            "message", "parent set",
            "child", childName,
            "parent", parentName
        )).build();
    }

    @DELETE
    @Path("/roles/{childName}/parent")
    public Response clearRoleParent(@PathParam("childName") String childName) {
        Optional<Role> childOpt = roleRepository.findByName(childName);
        if (childOpt.isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(Map.of("message", "role not found")).build();
        }
        roleRepository.setParent(childOpt.get().id, null);
        return Response.ok(Map.of("message", "parent cleared", "child", childName)).build();
    }

    @GET
    @Path("/keys")
    public Response listKeys() {
        List<Map<String, Object>> entries = rsaKeyProvider.allPublicKeys().keySet().stream()
            .map(kid -> {
                Map<String, Object> m = new java.util.LinkedHashMap<>();
                m.put("kid", kid);
                m.put("active", kid.equals(rsaKeyProvider.keyId()));
                return m;
            })
            .toList();
        return Response.ok(Map.of("activeKid", rsaKeyProvider.keyId(), "keys", entries)).build();
    }

    @DELETE
    @Path("/keys/{kid}")
    public Response retireKey(@PathParam("kid") String kid, @Context HttpHeaders headers) {
        UserSession actor = sessionService
            .findActiveSession(BearerExtractor.extract(headers))
            .orElseThrow();
        try {
            boolean removed = rsaKeyProvider.retire(kid);
            if (!removed) {
                return Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("message", "kid not found")).build();
            }
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", e.getMessage())).build();
        }
        LOG.infof("RSA signing key kid=%s retired by admin user=%s id=%s",
            kid, actor.user.username, actor.user.id);
        return Response.noContent().build();
    }

    @POST
    @Path("/keys/rotate")
    public Response rotateKey(@Context HttpHeaders headers) {
        UserSession actor = sessionService
            .findActiveSession(BearerExtractor.extract(headers))
            .orElseThrow();
        String previousKid = rsaKeyProvider.keyId();
        String newKid = rsaKeyProvider.rotate();
        // High-impact action: log who triggered it so post-incident forensics
        // can answer "who rotated the signing key on date X?". RoleFilter already
        // guarantees actor != null and has admin role.
        LOG.infof("RSA signing key rotated by admin user=%s id=%s — %s -> %s",
            actor.user.username, actor.user.id, previousKid, newKid);
        return Response.ok(Map.of(
            "message", "key rotated",
            "previousKid", previousKid,
            "newActiveKid", newKid
        )).build();
    }

    @GET
    @Path("/clients")
    public Response listClients() {
        List<ClientSummary> clients = clientRepository.findAll().stream()
            .map(ClientSummary::from)
            .toList();
        return Response.ok(clients).build();
    }

    @GET
    @Path("/clients/{id}")
    public Response getClient(@PathParam("id") String idStr) {
        UUID id;
        try {
            id = UUID.fromString(idStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid id")).build();
        }
        return clientRepository.findById(id)
            .map(c -> Response.ok(ClientSummary.from(c)).build())
            .orElseGet(() -> Response.status(Response.Status.NOT_FOUND)
                .entity(Map.of("message", "client not found")).build());
    }

    @POST
    @Path("/clients")
    public Response createClient(ClientRequest body) {
        if (body == null || body.clientId() == null || body.clientId().isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "clientId is required")).build();
        }
        if (clientRepository.findByClientId(body.clientId()).isPresent()) {
            return Response.status(Response.Status.CONFLICT)
                .entity(Map.of("message", "clientId already exists")).build();
        }

        Client client = new Client();
        client.id = UUID.randomUUID();
        client.clientId = body.clientId();
        // Hash the secret at rest. Plaintext input is consumed only here; the
        // admin must record it now because the server can't recover it later.
        client.clientSecret = body.clientSecret() == null || body.clientSecret().isBlank()
            ? null
            : ClientSecretHasher.hash(body.clientSecret());
        client.name = body.name();
        client.type = body.type() == null ? "public" : body.type();
        client.scopes = body.scopes();
        client.grantTypes = body.grantTypes();
        client.responseTypes = body.responseTypes();
        client.pkceRequired = body.pkceRequired() == null ? true : body.pkceRequired();
        client.enabled = body.enabled() == null ? true : body.enabled();
        client.baseUrl = body.baseUrl();
        client.description = body.description();
        client.frontchannelLogoutUri = body.frontchannelLogoutUri();
        client.backchannelLogoutUri = body.backchannelLogoutUri();
        client.createdAt = java.time.LocalDateTime.now();
        client.updatedAt = java.time.LocalDateTime.now();
        clientRepository.persist(client);

        return Response.status(Response.Status.CREATED)
            .entity(ClientSummary.from(clientRepository.findById(client.id).orElse(client)))
            .build();
    }

    @PUT
    @Path("/clients/{id}")
    public Response updateClient(@PathParam("id") String idStr, ClientRequest body) {
        UUID id;
        try {
            id = UUID.fromString(idStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid id")).build();
        }
        Client existing = clientRepository.findById(id).orElse(null);
        if (existing == null) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(Map.of("message", "client not found")).build();
        }
        if (body == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "request body required")).build();
        }

        if (body.clientSecret() != null && !body.clientSecret().isBlank()) {
            existing.clientSecret = ClientSecretHasher.hash(body.clientSecret());
        }
        if (body.name() != null) existing.name = body.name();
        if (body.type() != null) existing.type = body.type();
        if (body.scopes() != null) existing.scopes = body.scopes();
        if (body.grantTypes() != null) existing.grantTypes = body.grantTypes();
        if (body.responseTypes() != null) existing.responseTypes = body.responseTypes();
        if (body.pkceRequired() != null) existing.pkceRequired = body.pkceRequired();
        if (body.enabled() != null) existing.enabled = body.enabled();
        if (body.baseUrl() != null) existing.baseUrl = body.baseUrl();
        if (body.description() != null) existing.description = body.description();
        if (body.frontchannelLogoutUri() != null) existing.frontchannelLogoutUri = body.frontchannelLogoutUri();
        if (body.backchannelLogoutUri() != null) existing.backchannelLogoutUri = body.backchannelLogoutUri();
        existing.updatedAt = java.time.LocalDateTime.now();

        clientRepository.update(existing);
        return Response.ok(ClientSummary.from(
            clientRepository.findById(id).orElse(existing)
        )).build();
    }

    @DELETE
    @Path("/clients/{id}")
    public Response deleteClient(@PathParam("id") String idStr) {
        UUID id;
        try {
            id = UUID.fromString(idStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid id")).build();
        }
        clientRepository.delete(id);
        return Response.noContent().build();
    }

    @POST
    @Path("/clients/{id}/redirect-uris")
    public Response addRedirectUri(@PathParam("id") String idStr, Map<String, String> body) {
        UUID id;
        try {
            id = UUID.fromString(idStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid id")).build();
        }
        String uri = body == null ? null : body.get("uri");
        if (uri == null || uri.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "uri is required")).build();
        }
        // Reject schemes that turn a redirect into script execution / file access.
        // Only http(s) and a few well-known native-app schemes are allowed. The
        // exact-match check at /authorize already prevents *unregistered* URIs
        // from being used, but a malicious or sloppy admin could otherwise pin
        // `javascript:alert(1)` here and turn the authorize response into XSS.
        String trimmed = uri.trim();
        String lower = trimmed.toLowerCase();
        boolean allowedScheme =
            lower.startsWith("http://")
                || lower.startsWith("https://")
                || lower.matches("^[a-z][a-z0-9+.-]*://.*");  // custom mobile/native schemes
        boolean blockedScheme =
            lower.startsWith("javascript:")
                || lower.startsWith("data:")
                || lower.startsWith("file:")
                || lower.startsWith("vbscript:");
        if (!allowedScheme || blockedScheme) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "redirect_uri must use http(s) or a registered native scheme"))
                .build();
        }

        Client client = clientRepository.findById(id).orElse(null);
        if (client == null) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(Map.of("message", "client not found")).build();
        }

        RedirectUri redirectUri = new RedirectUri();
        redirectUri.id = UUID.randomUUID();
        redirectUri.client = client;
        redirectUri.uri = trimmed;
        redirectUri.createdAt = java.time.LocalDateTime.now();
        clientRepository.addRedirectUri(redirectUri);

        return Response.ok(ClientSummary.from(
            clientRepository.findById(id).orElse(client)
        )).build();
    }

    @DELETE
    @Path("/clients/{id}/redirect-uris/{uriId}")
    public Response removeRedirectUri(
        @PathParam("id") String idStr,
        @PathParam("uriId") String uriIdStr
    ) {
        UUID uriId;
        try {
            uriId = UUID.fromString(uriIdStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid uriId")).build();
        }
        clientRepository.removeRedirectUri(uriId);
        return Response.noContent().build();
    }

    // ---- Sessions ----

    @GET
    @Path("/sessions")
    public Response listSessions() {
        List<SessionSummary> sessions = sessionRepository.findAllActive().stream()
            .map(SessionSummary::from)
            .toList();
        return Response.ok(sessions).build();
    }

    @GET
    @Path("/users/{userId}/sessions")
    public Response listSessionsForUser(@PathParam("userId") String userIdStr) {
        UUID userId;
        try {
            userId = UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid userId")).build();
        }
        List<SessionSummary> sessions = sessionRepository.findActiveByUserId(userId).stream()
            .map(SessionSummary::from)
            .toList();
        return Response.ok(sessions).build();
    }

    @DELETE
    @Path("/sessions/{id}")
    public Response revokeSession(@PathParam("id") String idStr) {
        UUID id;
        try {
            id = UUID.fromString(idStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid id")).build();
        }
        refreshTokenRepository.revokeBySessionId(id);
        sessionRepository.deleteById(id);
        return Response.noContent().build();
    }

    // ---- Consents ----

    @GET
    @Path("/users/{userId}/consents")
    public Response listConsentsForUser(@PathParam("userId") String userIdStr) {
        UUID userId;
        try {
            userId = UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid userId")).build();
        }
        List<UserConsent> consents = userConsentRepository.findByUserId(userId);
        List<ConsentSummary> summaries = consents.stream()
            .map(c -> ConsentSummary.from(c,
                clientRepository.findById(c.clientId).orElse(null)))
            .toList();
        return Response.ok(summaries).build();
    }

    @DELETE
    @Path("/consents/{id}")
    public Response revokeConsent(@PathParam("id") String idStr) {
        UUID id;
        try {
            id = UUID.fromString(idStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid id")).build();
        }
        userConsentRepository.deleteById(id);
        return Response.noContent().build();
    }

    // ---- User CRUD ----

    @GET
    @Path("/users/{userId}")
    public Response getUser(@PathParam("userId") String userIdStr) {
        UUID userId;
        try {
            userId = UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid userId")).build();
        }
        return userRepository.findById(userId)
            .map(u -> Response.ok(UserSummary.from(u,
                roleRepository.findNamesByUserId(u.id))).build())
            .orElseGet(() -> Response.status(Response.Status.NOT_FOUND)
                .entity(Map.of("message", "user not found")).build());
    }

    @POST
    @Path("/users")
    public Response createUser(UserCreateRequest body) {
        if (body == null
            || body.email() == null || body.email().isBlank()
            || body.username() == null || body.username().isBlank()
            || body.password() == null || body.password().length() < 8) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message",
                    "email, username, password (>=8 chars) are required"))
                .build();
        }
        String normalizedEmail = body.email().trim().toLowerCase();
        String normalizedUsername = body.username().trim().toLowerCase();
        if (userRepository.findByEmail(normalizedEmail).isPresent()) {
            return Response.status(Response.Status.CONFLICT)
                .entity(Map.of("message", "email already registered")).build();
        }
        if (userRepository.findByUsername(normalizedUsername).isPresent()) {
            return Response.status(Response.Status.CONFLICT)
                .entity(Map.of("message", "username already taken")).build();
        }

        User user = new User();
        user.id = UUID.randomUUID();
        user.email = normalizedEmail;
        user.username = normalizedUsername;
        user.firstName = body.firstName();
        user.lastName = body.lastName();
        user.enabled = body.enabled() == null ? true : body.enabled();
        user.emailVerified = body.emailVerified() == null ? false : body.emailVerified();
        user.createdAt = java.time.LocalDateTime.now();
        user.updatedAt = java.time.LocalDateTime.now();
        userRepository.persist(user);

        Map<String, String> argon2 = Argon2Hasher.hash(body.password());
        Credential credential = new Credential();
        credential.id = UUID.randomUUID();
        credential.user = user;
        credential.type = "password";
        credential.secretData = argon2.get("secretData");
        credential.credentialData = argon2.get("credentialData");
        credential.createdAt = java.time.LocalDateTime.now();
        credential.updatedAt = java.time.LocalDateTime.now();
        credentialRepository.persist(credential);

        roleRepository.findByName("user").ifPresent(role ->
            roleRepository.assignToUser(user.id, role.id)
        );

        return Response.status(Response.Status.CREATED)
            .entity(UserSummary.from(user, roleRepository.findNamesByUserId(user.id)))
            .build();
    }

    @jakarta.ws.rs.PATCH
    @Path("/users/{userId}")
    public Response updateUser(
        @PathParam("userId") String userIdStr,
        UserUpdateRequest body
    ) {
        UUID userId;
        try {
            userId = UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid userId")).build();
        }
        if (body == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "request body required")).build();
        }
        User user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(Map.of("message", "user not found")).build();
        }

        boolean oldEmailVerified = user.emailVerified;
        boolean kickSessions = false;
        boolean emailVerifiedCacheOnly = false;

        if (body.firstName() != null) user.firstName = body.firstName();
        if (body.lastName() != null) user.lastName = body.lastName();
        if (body.enabled() != null) {
            user.enabled = body.enabled();
            if (!body.enabled()) kickSessions = true;
        }
        
        if (body.emailVerified() != null) {
            user.emailVerified = body.emailVerified();
            if (oldEmailVerified && !body.emailVerified()) {
                kickSessions = true;
            } else if (oldEmailVerified != body.emailVerified()) {
                emailVerifiedCacheOnly = true;
            }
        }

        if (kickSessions) {
            sessionRepository.deleteAllByUserId(userId);
        }

        user.updatedAt = java.time.LocalDateTime.now();
        userRepository.update(user);

        if (!kickSessions && emailVerifiedCacheOnly) {
            sessionRepository.invalidateCacheByUserId(userId);
        }

        if (body.newPassword() != null && !body.newPassword().isBlank()) {
            if (body.newPassword().length() < 8) {
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("message", "password must be at least 8 characters"))
                    .build();
            }
            Credential cred = credentialRepository
                .findFirstByUserIdAndType(userId, "password")
                .orElse(null);
            Map<String, String> argon2 = Argon2Hasher.hash(body.newPassword());
            if (cred == null) {
                cred = new Credential();
                cred.id = UUID.randomUUID();
                cred.user = user;
                cred.type = "password";
                cred.createdAt = java.time.LocalDateTime.now();
                cred.secretData = argon2.get("secretData");
                cred.credentialData = argon2.get("credentialData");
                cred.updatedAt = java.time.LocalDateTime.now();
                credentialRepository.persist(cred);
            } else {
                cred.secretData = argon2.get("secretData");
                cred.credentialData = argon2.get("credentialData");
                cred.updatedAt = java.time.LocalDateTime.now();
                credentialRepository.update(cred);
            }
            sessionRepository.deleteAllByUserId(userId);
        }

        return Response.ok(UserSummary.from(user,
            roleRepository.findNamesByUserId(userId))).build();
    }

    @DELETE
    @Path("/users/{userId}")
    public Response deleteUser(
        @PathParam("userId") String userIdStr,
        @Context HttpHeaders headers
    ) {
        UUID userId;
        try {
            userId = UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "invalid userId")).build();
        }

        UserSession current = sessionService
            .findActiveSession(BearerExtractor.extract(headers))
            .orElse(null);
        if (current != null && current.user.id.equals(userId)) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "cannot delete your own account")).build();
        }

        sessionRepository.deleteAllByUserId(userId);
        userRepository.delete(userId);
        return Response.noContent().build();
    }

}
