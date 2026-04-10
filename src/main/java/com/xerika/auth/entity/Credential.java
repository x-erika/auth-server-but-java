package com.xerika.auth.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "credentials")
public class Credential {

    @Id
    @Column(name = "id", nullable = false)
    public UUID id;

    @Column(name = "type", nullable = false)
    public String type;

    @Column(name = "secret_data", columnDefinition = "TEXT")
    public String secretData;

    @Column(name = "credential_data", columnDefinition = "TEXT")
    public String credentialData;

    @Column(name = "created_at")
    public LocalDateTime createdAt;

    @Column(name = "updated_at")
    public LocalDateTime updatedAt;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    public User user;
}
