package com.xerika.auth.login.dto;

import com.xerika.auth.user.User;

import java.util.List;

public record UserPayload(
    String id,
    String email,
    String username,
    boolean emailVerified,
    List<String> roles
) {

    public static UserPayload from(User user, List<String> roles) {
        return new UserPayload(
            user.id.toString(),
            user.email,
            user.username,
            user.emailVerified,
            roles
        );
    }
}
