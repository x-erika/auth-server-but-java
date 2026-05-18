package com.xerika.auth.oauth.device;

import java.time.LocalDateTime;
import java.util.UUID;

public class DeviceAuthorization {

    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_APPROVED = "approved";
    public static final String STATUS_DENIED = "denied";
    public static final String STATUS_CONSUMED = "consumed";

    public UUID id;
    public String deviceCode;
    public String userCode;
    public String clientId;
    public String scope;
    public String status;
    public UUID userId;
    public UUID sessionId;
    public LocalDateTime expiresAt;
    public LocalDateTime createdAt;
}
