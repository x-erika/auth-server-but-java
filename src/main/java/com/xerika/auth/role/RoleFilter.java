package com.xerika.auth.role;

import com.xerika.auth.common.web.BearerExtractor;
import com.xerika.auth.session.SessionService;
import com.xerika.auth.session.UserSession;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Provider
public class RoleFilter implements ContainerRequestFilter {

    @Context
    ResourceInfo resourceInfo;

    @Inject
    SessionService sessionService;

    @Inject
    RoleRepository roleRepository;

    @Override
    public void filter(ContainerRequestContext ctx) {
        Method method = resourceInfo.getResourceMethod();
        if (method == null) {
            return;
        }

        RequiresRole requirement = method.getAnnotation(RequiresRole.class);
        if (requirement == null) {
            requirement = method.getDeclaringClass().getAnnotation(RequiresRole.class);
        }
        if (requirement == null) {
            return;
        }

        String[] required = requirement.value();
        if (required == null || required.length == 0) {
            return;
        }

        String token = BearerExtractor.extract(ctx);
        Optional<UserSession> sessionOpt = sessionService.findActiveSession(token);
        if (sessionOpt.isEmpty()) {
            ctx.abortWith(Response.status(Response.Status.UNAUTHORIZED)
                .entity(Map.of("message", "authentication required"))
                .build());
            return;
        }

        UserSession session = sessionOpt.get();
        Set<String> userRoles = Set.copyOf(roleRepository.findNamesByUserId(session.user.id));

        boolean granted = false;
        for (String role : required) {
            if (userRoles.contains(role)) {
                granted = true;
                break;
            }
        }

        if (!granted) {
            ctx.abortWith(Response.status(Response.Status.FORBIDDEN)
                .entity(Map.of(
                    "message", "forbidden",
                    "required_roles", List.of(required)
                ))
                .build());
        }
    }
}
