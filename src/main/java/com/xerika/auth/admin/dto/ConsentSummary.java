package com.xerika.auth.admin.dto;

import com.xerika.auth.client.Client;
import com.xerika.auth.oauth.consent.UserConsent;

public record ConsentSummary(
    String id,
    String clientUuid,
    String clientId,
    String clientName,
    String scopes,
    String grantedAt,
    String updatedAt
) {

    public static ConsentSummary from(UserConsent consent, Client client) {
        return new ConsentSummary(
            consent.id.toString(),
            consent.clientId.toString(),
            client == null ? null : client.clientId,
            client == null ? null : client.name,
            consent.scopes,
            consent.grantedAt == null ? null : consent.grantedAt.toString(),
            consent.updatedAt == null ? null : consent.updatedAt.toString()
        );
    }
}
