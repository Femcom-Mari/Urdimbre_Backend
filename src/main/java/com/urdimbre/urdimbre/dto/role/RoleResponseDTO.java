package com.urdimbre.urdimbre.dto.role;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RoleResponseDTO {

    private Long id;
    private String name;
    private String description;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String createdBy;
    private String lastModifiedBy;

    public String getDisplayName() {
        if (name != null && name.startsWith("ROLE_")) {
            return name.substring(5);
        }
        return name;
    }

    public boolean isAdminRole() {
        return "ROLE_ADMIN".equals(name);
    }

    public boolean isOrganizerRole() {
        return "ROLE_ORGANIZER".equals(name);
    }

    public boolean isUserRole() {
        return "ROLE_USER".equals(name);
    }
}