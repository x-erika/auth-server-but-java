package com.xerika.auth.admin.dto;

import com.xerika.auth.client.Client;
import com.xerika.auth.client.RedirectUri;

import java.util.List;

public record ClientSummary(
    String id,
    String clientId,
    String name,
    String type,
    String scopes,
    String grantTypes,
    String responseTypes,
    boolean pkceRequired,
    boolean enabled,
    String baseUrl,
    String description,
    String frontchannelLogoutUri,
    String backchannelLogoutUri,
    List<RedirectUriSummary> redirectUris
) {

    public static ClientSummary from(Client client) {
        List<RedirectUriSummary> uris = client.redirectUris == null
            ? List.of()
            : client.redirectUris.stream().map(RedirectUriSummary::from).toList();

        return new ClientSummary(
            client.id.toString(),
            client.clientId,
            client.name,
            client.type,
            client.scopes,
            client.grantTypes,
            client.responseTypes,
            client.pkceRequired,
            client.enabled,
            client.baseUrl,
            client.description,
            client.frontchannelLogoutUri,
            client.backchannelLogoutUri,
            uris
        );
    }

    public record RedirectUriSummary(String id, String uri) {
        public static RedirectUriSummary from(RedirectUri r) {
            return new RedirectUriSummary(r.id.toString(), r.uri);
        }
    }
}
