package com.xerika.auth.service;

import com.xerika.auth.entity.Client;
import com.xerika.auth.entity.RedirectUri;
import com.xerika.auth.repository.ClientRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import io.quarkus.runtime.StartupEvent;

import java.time.LocalDateTime;
import java.util.UUID;

@ApplicationScoped
public class ClientBootstrapService {

    @Inject
    ClientRepository clientRepository;

    @PersistenceContext
    EntityManager em;

    @Transactional
    void onStart(@Observes StartupEvent ev) {
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
}
