package com.xerika.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "roles")
public class Role {

    @Id
    public UUID id;

    @Column(unique = true, nullable = false)
    public String name;

    public String description;

    public LocalDateTime createdAt;

    @ManyToMany(mappedBy = "roles")
    public List<User> users;
}