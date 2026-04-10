package com.xerika.auth.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "clients")
public class Client {

    @Id
    @Column(name = "id", nullable = false)
    public UUID id;

    @Column(name = "client_id", unique = true, nullable = false)
    public String clientId;

    @Column(name = "client_secret", columnDefinition = "TEXT")
    public String clientSecret;

    @Column(name = "name")
    public String name;

    @Column(name = "type")
    public String type;

    @Column(name = "grant_types", columnDefinition = "TEXT")
    public String grantTypes;

    @Column(name = "response_types", columnDefinition = "TEXT")
    public String responseTypes;

    @Column(name = "scopes", columnDefinition = "TEXT")
    public String scopes;

    @Column(name = "pkce_required")
    public boolean pkceRequired;

    @Column(name = "enabled")
    public boolean enabled;

    @Column(name = "base_url", columnDefinition = "TEXT")
    public String baseUrl;

    @Column(name = "description", columnDefinition = "TEXT")
    public String description;

    @Column(name = "access_token_ttl")
    public Integer accessTokenTtl;

    @Column(name = "refresh_token_ttl")
    public Integer refreshTokenTtl;

    @Column(name = "created_at")
    public LocalDateTime createdAt;

    @Column(name = "updated_at")
    public LocalDateTime updatedAt;

    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL)
    public List<RedirectUri> redirectUris;
}
