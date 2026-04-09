package com.xerika.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "clients")
public class Client {

    @Id
    public UUID id;

    @Column(unique = true, nullable = false)
    public String clientId;

    public String clientSecret;
    public String name;

    public String type;

    @Column(columnDefinition = "TEXT")
    public String grantTypes;

    @Column(columnDefinition = "TEXT")
    public String responseTypes;

    @Column(columnDefinition = "TEXT")
    public String scopes;

    public boolean pkceRequired;
    public boolean enabled;

    public String baseUrl;
    public String description;

    public Integer accessTokenTtl;
    public Integer refreshTokenTtl;

    public LocalDateTime createdAt;
    public LocalDateTime updatedAt;

    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL)
    public List<RedirectUri> redirectUris;
}