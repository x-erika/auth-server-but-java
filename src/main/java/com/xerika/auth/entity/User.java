package com.xerika.auth.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {

    @Id
    @Column(name = "id", nullable = false)
    public UUID id;

    @Column(name = "email", unique = true, nullable = false)
    public String email;

    @Column(name = "email_verified")
    public boolean emailVerified;

    @Column(name = "username", unique = true, nullable = false)
    public String username;

    @Column(name = "first_name")
    public String firstName;

    @Column(name = "last_name")
    public String lastName;

    @Column(name = "enabled")
    public boolean enabled;

    @Column(name = "created_at")
    public LocalDateTime createdAt;

    @Column(name = "updated_at")
    public LocalDateTime updatedAt;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    public List<Credential> credentials;

    @OneToMany(mappedBy = "user")
    public List<UserSession> sessions;

    @ManyToMany
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    public List<Role> roles;
}
