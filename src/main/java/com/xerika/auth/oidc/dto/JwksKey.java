package com.xerika.auth.oidc.dto;

public record JwksKey(
    String kty,
    String use,
    String alg,
    String kid,
    String n,
    String e
) {
}
