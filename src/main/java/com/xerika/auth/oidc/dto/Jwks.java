package com.xerika.auth.oidc.dto;

import java.util.List;

public record Jwks(List<JwksKey> keys) {
}
