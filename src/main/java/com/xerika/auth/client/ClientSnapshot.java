package com.xerika.auth.client;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class ClientSnapshot {

    public UUID id;
    public String clientId;
    public String clientSecret;
    public String name;
    public String type;
    public String grantTypes;
    public String responseTypes;
    public String scopes;
    public boolean pkceRequired;
    public boolean enabled;
    public String baseUrl;
    public String description;
    public Integer accessTokenTtl;
    public Integer refreshTokenTtl;
    public String frontchannelLogoutUri;
    public String backchannelLogoutUri;
    public LocalDateTime createdAt;
    public LocalDateTime updatedAt;
    public List<RedirectUriSnapshot> redirectUris = new ArrayList<>();

    public static class RedirectUriSnapshot {
        public UUID id;
        public String uri;
        public LocalDateTime createdAt;
    }

    public static ClientSnapshot from(Client c) {
        ClientSnapshot s = new ClientSnapshot();
        s.id = c.id;
        s.clientId = c.clientId;
        s.clientSecret = c.clientSecret;
        s.name = c.name;
        s.type = c.type;
        s.grantTypes = c.grantTypes;
        s.responseTypes = c.responseTypes;
        s.scopes = c.scopes;
        s.pkceRequired = c.pkceRequired;
        s.enabled = c.enabled;
        s.baseUrl = c.baseUrl;
        s.description = c.description;
        s.accessTokenTtl = c.accessTokenTtl;
        s.refreshTokenTtl = c.refreshTokenTtl;
        s.frontchannelLogoutUri = c.frontchannelLogoutUri;
        s.backchannelLogoutUri = c.backchannelLogoutUri;
        s.createdAt = c.createdAt;
        s.updatedAt = c.updatedAt;
        if (c.redirectUris != null) {
            for (RedirectUri r : c.redirectUris) {
                RedirectUriSnapshot ru = new RedirectUriSnapshot();
                ru.id = r.id;
                ru.uri = r.uri;
                ru.createdAt = r.createdAt;
                s.redirectUris.add(ru);
            }
        }
        return s;
    }

    public Client toEntity() {
        Client c = new Client();
        c.id = id;
        c.clientId = clientId;
        c.clientSecret = clientSecret;
        c.name = name;
        c.type = type;
        c.grantTypes = grantTypes;
        c.responseTypes = responseTypes;
        c.scopes = scopes;
        c.pkceRequired = pkceRequired;
        c.enabled = enabled;
        c.baseUrl = baseUrl;
        c.description = description;
        c.accessTokenTtl = accessTokenTtl;
        c.refreshTokenTtl = refreshTokenTtl;
        c.frontchannelLogoutUri = frontchannelLogoutUri;
        c.backchannelLogoutUri = backchannelLogoutUri;
        c.createdAt = createdAt;
        c.updatedAt = updatedAt;
        c.redirectUris = new ArrayList<>();
        if (redirectUris != null) {
            for (RedirectUriSnapshot ru : redirectUris) {
                RedirectUri r = new RedirectUri();
                r.id = ru.id;
                r.client = c;
                r.uri = ru.uri;
                r.createdAt = ru.createdAt;
                c.redirectUris.add(r);
            }
        }
        return c;
    }
}
