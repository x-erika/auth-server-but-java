package com.xerika.auth.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "roles")
public class Role {

    @Id
    @Column(name = "id", nullable = false)
    public UUID id;

    @Column(name = "name", unique = true, nullable = false)
    public String name;

    @Column(name = "description", columnDefinition = "TEXT")
    public String description;

    @Column(name = "created_at")
    public LocalDateTime createdAt;

    @ManyToMany(mappedBy = "roles")
    public List<User> users;
}
