package com.xerika.auth.service;

import com.xerika.auth.entity.User;
import com.xerika.auth.util.JwtUtil;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class TokenService {

    private static final String DEFAULT_SECRET = "change-me-in-config";

    public String issueAccessToken(User user) {
        return JwtUtil.sign(user.id.toString(), DEFAULT_SECRET);
    }
}
