package com.xerika.auth.oauth.device;

import com.xerika.auth.session.UserSession;
import com.xerika.auth.user.User;
import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "device_authorizations")
public class DeviceAuthorization {

    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_APPROVED = "approved";
    public static final String STATUS_DENIED = "denied";
    public static final String STATUS_CONSUMED = "consumed";

    @Id
    @Column(name = "id", nullable = false)
    public UUID id;

    @Column(name = "device_code", unique = true, nullable = false)
    public String deviceCode;

    @Column(name = "user_code", unique = true, nullable = false)
    public String userCode;

    @Column(name = "client_id", nullable = false)
    public String clientId;

    @Column(name = "scope", columnDefinition = "TEXT")
    public String scope;

    @Column(name = "status", nullable = false)
    public String status;

    @ManyToOne
    @JoinColumn(name = "user_id")
    public User user;

    @ManyToOne
    @JoinColumn(name = "session_id")
    public UserSession session;

    @Column(name = "expires_at", nullable = false)
    public LocalDateTime expiresAt;

    @Column(name = "created_at")
    public LocalDateTime createdAt;
}
