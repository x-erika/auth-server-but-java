package com.xerika.auth.common.web;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;

import java.util.Map;

public final class BearerExtractor {

    public static final String SESSION_COOKIE = "session_token";

    private BearerExtractor() {
    }

    public static String extract(HttpHeaders headers) {
        String fromHeader = extractFromHeaders(headers::getHeaderString);
        if (fromHeader != null && !fromHeader.isBlank()) {
            return fromHeader;
        }
        Map<String, Cookie> cookies = headers.getCookies();
        Cookie cookie = cookies == null ? null : cookies.get(SESSION_COOKIE);
        return cookie == null ? null : cookie.getValue();
    }

    public static String extract(ContainerRequestContext ctx) {
        String fromHeader = extractFromHeaders(ctx::getHeaderString);
        if (fromHeader != null && !fromHeader.isBlank()) {
            return fromHeader;
        }
        Map<String, Cookie> cookies = ctx.getCookies();
        Cookie cookie = cookies == null ? null : cookies.get(SESSION_COOKIE);
        return cookie == null ? null : cookie.getValue();
    }

    private static String extractFromHeaders(java.util.function.Function<String, String> getter) {
        String bearer = getter.apply(HttpHeaders.AUTHORIZATION);
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7).trim();
        }
        return getter.apply("X-Session-Token");
    }
}
