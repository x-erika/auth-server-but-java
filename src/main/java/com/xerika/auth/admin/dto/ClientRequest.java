package com.xerika.auth.admin.dto;

public record ClientRequest(
    String clientId,
    String clientSecret,
    String name,
    String type,
    String scopes,
    String grantTypes,
    String responseTypes,
    Boolean pkceRequired,
    Boolean enabled,
    String baseUrl,
    String description,
    String frontchannelLogoutUri,
    String backchannelLogoutUri
) {
}
