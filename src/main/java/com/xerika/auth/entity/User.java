package com.xerika.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {

    @Id
    public UUID id;

    @Column(unique = true, nullable = false)
    public String email;

    public boolean emailVerified;

    @Column(unique = true, nullable = false)
    public String username;

    public String firstName;
    public String lastName;

    public boolean enabled;

    public LocalDateTime createdAt;
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