package com.xerika.auth.oauth.consent;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "user_consents")
public class UserConsent {

    @Id
    @Column(name = "id", nullable = false)
    public UUID id;

    @Column(name = "user_id", nullable = false)
    public UUID userId;

    @Column(name = "client_id", nullable = false)
    public UUID clientId;

    @Column(name = "scopes", nullable = false, columnDefinition = "TEXT")
    public String scopes;

    @Column(name = "granted_at")
    public LocalDateTime grantedAt;

    @Column(name = "updated_at")
    public LocalDateTime updatedAt;
}
