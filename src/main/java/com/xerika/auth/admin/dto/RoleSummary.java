package com.xerika.auth.admin.dto;

import com.xerika.auth.role.Role;

public record RoleSummary(String id, String name, String description) {

    public static RoleSummary from(Role role) {
        return new RoleSummary(role.id.toString(), role.name, role.description);
    }
}
