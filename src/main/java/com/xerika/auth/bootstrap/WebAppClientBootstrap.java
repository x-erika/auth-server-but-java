package com.xerika.auth.bootstrap;

import com.xerika.auth.client.Client;
import com.xerika.auth.client.ClientRepository;
import com.xerika.auth.client.RedirectUri;
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

    @Inject
    ClientRepository clientRepository;

    @PersistenceContext
    EntityManager em;

    @Transactional
    void onStart(@Observes StartupEvent ev) {
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
        if (clientRepository.findByClientId("service-client").isPresent()) {
            return;
        }

        Client client = new Client();
        client.id = UUID.randomUUID();
        client.clientId = "service-client";
        client.clientSecret = "service-secret-change-me";
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
