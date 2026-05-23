package com.xerika.auth.common.web;

import io.vertx.ext.web.RoutingContext;

/**
 * Resolves the originating client IP for rate-limit and audit purposes.
 *
 * <p>Always reads from Vert.x {@code remoteAddress()} rather than parsing the
 * {@code X-Forwarded-For} header directly. Whether {@code remoteAddress()}
 * already reflects the XFF value is controlled at the platform level by the
 * {@code quarkus.http.proxy.*} settings (proxy-address-forwarding +
 * trusted-proxies allowlist).
 *
 * <p>That keeps the trust boundary in one place: the operator configures which
 * proxies are trusted; application code does not have to decide whether to
 * believe an XFF header. A client that hits the server directly cannot spoof
 * its source IP by sending {@code X-Forwarded-For: 1.2.3.4} because Quarkus
 * will reject the header (or never apply it) unless the TCP peer matches the
 * trusted-proxies list.
 */
public final class ClientIp {

    private ClientIp() {
    }

    public static String from(RoutingContext ctx) {
        if (ctx == null) {
            return null;
        }
        var addr = ctx.request().remoteAddress();
        return addr == null ? null : addr.host();
    }
}
