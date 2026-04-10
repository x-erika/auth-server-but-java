package com.xerika.auth.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "redirect_uris")
public class RedirectUri {

    @Id
    @Column(name = "id", nullable = false)
    public UUID id;

    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    public Client client;

    @Column(name = "uri", columnDefinition = "TEXT", nullable = false)
    public String uri;

    @Column(name = "created_at")
    public LocalDateTime createdAt;
}
