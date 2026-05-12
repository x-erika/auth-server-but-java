package com.xerika.auth.oauth.logout;

import com.xerika.auth.client.Client;
import com.xerika.auth.common.crypto.JwtSigner;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@ApplicationScoped
public class BackchannelLogoutNotifier {

    private static final Logger LOG = Logger.getLogger(BackchannelLogoutNotifier.class);

    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "backchannel-logout");
        t.setDaemon(true);
        return t;
    });

    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build();

    @Inject
    JwtSigner jwtSigner;

    public CompletableFuture<Void> notifyClient(Client client, UUID userId, UUID sessionId) {
        if (client.backchannelLogoutUri == null || client.backchannelLogoutUri.isBlank()) {
            return CompletableFuture.completedFuture(null);
        }

        return CompletableFuture.runAsync(() -> sendLogoutToken(client, userId, sessionId), executor);
    }

    private void sendLogoutToken(Client client, UUID userId, UUID sessionId) {
        try {
            String logoutToken = jwtSigner.signLogoutToken(
                userId == null ? null : userId.toString(),
                client.clientId,
                sessionId.toString()
            );

            String body = "logout_token=" + URLEncoder.encode(logoutToken, StandardCharsets.UTF_8);

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(client.backchannelLogoutUri))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                LOG.infof("Backchannel logout delivered to %s (client=%s, sid=%s)",
                    client.backchannelLogoutUri, client.clientId, sessionId);
            } else {
                LOG.warnf("Backchannel logout to %s returned %d", client.backchannelLogoutUri, response.statusCode());
            }
        } catch (Exception e) {
            LOG.warnf(e, "Backchannel logout to %s failed", client.backchannelLogoutUri);
        }
    }
}
