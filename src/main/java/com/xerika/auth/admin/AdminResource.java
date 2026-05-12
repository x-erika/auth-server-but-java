package com.xerika.auth.admin;

import com.xerika.auth.admin.dto.RoleSummary;
import com.xerika.auth.admin.dto.UserSummary;
import com.xerika.auth.common.crypto.RsaKeyProvider;
import com.xerika.auth.common.web.BearerExtractor;
import com.xerika.auth.role.RequiresRole;
import com.xerika.auth.role.Role;
import com.xerika.auth.role.RoleRepository;
import com.xerika.auth.session.SessionService;
import com.xerika.auth.session.UserSession;
import com.xerika.auth.user.User;
import com.xerika.auth.user.UserRepository;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Path("/admin")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@RequiresRole("admin")
public class AdminResource {

    @Inject
    SessionService sessionService;

    @Inject
    UserRepository userRepository;

    @Inject
    RoleRepository roleRepository;

    @Inject
    RsaKeyProvider rsaKeyProvider;

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
        if (child.id.equals(parent.id)) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "role cannot be its own parent")).build();
        }
        if (wouldCreateCycle(child.id, parent.id)) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Map.of("message", "cycle detected in role hierarchy")).build();
        }

        roleRepository.setParent(child.id, parent.id);
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
        return Response.ok(Map.of("active_kid", rsaKeyProvider.keyId(), "keys", entries)).build();
    }

    @POST
    @Path("/keys/rotate")
    public Response rotateKey() {
        String previousKid = rsaKeyProvider.keyId();
        String newKid = rsaKeyProvider.rotate();
        return Response.ok(Map.of(
            "message", "key rotated",
            "previous_kid", previousKid,
            "new_active_kid", newKid
        )).build();
    }

    private boolean wouldCreateCycle(UUID childId, UUID newParentId) {
        java.util.Map<UUID, UUID> parentOf = new java.util.HashMap<>();
        for (Role r : roleRepository.findAll()) {
            parentOf.put(r.id, r.parentId);
        }

        UUID cursor = newParentId;
        java.util.Set<UUID> seen = new java.util.HashSet<>();
        while (cursor != null) {
            if (cursor.equals(childId) || !seen.add(cursor)) {
                return true;
            }
            cursor = parentOf.get(cursor);
        }
        return false;
    }
}
