package com.xerika.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "credentials")
public class Credential {

    @Id
    public UUID id;

    public String type;

    @Column(columnDefinition = "TEXT")
    public String secretData;

    @Column(columnDefinition = "TEXT")
    public String credentialData;

    public LocalDateTime createdAt;
    public LocalDateTime updatedAt;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    public User user;
}