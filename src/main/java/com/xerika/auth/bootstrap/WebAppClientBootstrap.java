package com.xerika.auth.bootstrap;

import com.xerika.auth.client.Client;
import com.xerika.auth.client.ClientRepository;
import com.xerika.auth.client.ClientSecretHasher;
import com.xerika.auth.client.RedirectUri;
import org.jboss.logging.Logger;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@ApplicationScoped
public class WebAppClientBootstrap {

    private static final Logger LOG = Logger.getLogger(WebAppClientBootstrap.class);
    private static final String SERVICE_CLIENT_BOOTSTRAP_SECRET = "service-secret-change-me";

    @Inject
    ClientRepository clientRepository;

    @PersistenceContext
    EntityManager em;

    @Transactional
    void onStart(@Observes StartupEvent ev) {
        BootstrapLock.acquire(em);
        ensureWebApp();
        ensureServiceClient();
    }

    private void ensureWebApp() {
        if (clientRepository.findByClientId("web-app").isPresent()) {
            return;
        }

        Client client = new Client();
        client.id = UUID.randomUUID();
        client.clientId = "web-app";
        client.clientSecret = null;
        client.name = "Web App";
        client.type = "public";
        client.grantTypes = "authorization_code refresh_token";
        client.responseTypes = "code";
        client.scopes = "openid profile email";
        client.pkceRequired = true;
        client.enabled = true;
        client.baseUrl = "http://localhost:3000";
        client.description = "Bootstrap public client for local OAuth testing";
        client.accessTokenTtl = 900;
        client.refreshTokenTtl = 2592000;
        client.createdAt = LocalDateTime.now();
        client.updatedAt = LocalDateTime.now();

        em.persist(client);

        RedirectUri redirectUri = new RedirectUri();
        redirectUri.id = UUID.randomUUID();
        redirectUri.client = client;
        redirectUri.uri = "http://localhost:3000/callback";
        redirectUri.createdAt = LocalDateTime.now();

        em.persist(redirectUri);
    }

    private void ensureServiceClient() {
        Client existing = clientRepository.findByClientId("service-client").orElse(null);
        if (existing != null) {
            // One-time migration: pre-hashing deployments stored the bootstrap secret
            // verbatim. Detect that exact value and upgrade to Argon2 so the DB no
            // longer holds plaintext. Other plaintext secrets are admin-managed and
            // get a warning instead — admin must rotate via /admin/clients/{id}.
            if (SERVICE_CLIENT_BOOTSTRAP_SECRET.equals(existing.clientSecret)) {
                existing.clientSecret = ClientSecretHasher.hash(SERVICE_CLIENT_BOOTSTRAP_SECRET);
                em.merge(existing);
                LOG.info("Migrated service-client legacy plaintext bootstrap secret to Argon2 hash");
            } else if (existing.clientSecret != null
                && !existing.clientSecret.isBlank()
                && !ClientSecretHasher.isHashed(existing.clientSecret)) {
                LOG.warnf("Client '%s' has a plaintext secret — admin should rotate via /admin/clients/{id}",
                    existing.clientId);
            }
            return;
        }

        Client client = new Client();
        client.id = UUID.randomUUID();
        client.clientId = "service-client";
        client.clientSecret = ClientSecretHasher.hash(SERVICE_CLIENT_BOOTSTRAP_SECRET);
        client.name = "Service Client";
        client.type = "confidential";
        client.grantTypes = "client_credentials";
        client.responseTypes = "";
        client.scopes = "openid profile email";
        client.pkceRequired = false;
        client.enabled = true;
        client.description = "Confidential client for machine-to-machine (client_credentials)";
        client.accessTokenTtl = 900;
        client.refreshTokenTtl = 0;
        client.createdAt = LocalDateTime.now();
        client.updatedAt = LocalDateTime.now();

        em.persist(client);
    }
}
