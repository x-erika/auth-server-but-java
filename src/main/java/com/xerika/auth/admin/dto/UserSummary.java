package com.xerika.auth.admin.dto;

import com.xerika.auth.user.User;

import java.util.List;

public record UserSummary(
    String id,
    String email,
    String username,
    boolean enabled,
    boolean emailVerified,
    List<String> roles
) {

    public static UserSummary from(User user, List<String> roles) {
        return new UserSummary(
            user.id.toString(),
            user.email,
            user.username,
            user.enabled,
            user.emailVerified,
            roles
        );
    }
}
