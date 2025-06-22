package com.urdimbre.urdimbre.dto.user;

import java.util.List;
import java.util.Set;

import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDTO {
    private Long id;
    private String username;

    @Email(message = "Debe proporcionar una dirección de email válida")
    private String email;

    private String fullName;
    private String biography;
    private String location;
    private String profileImageUrl;

    private Set<String> pronouns;

    private String status;

    private String createdAt;
    private String updatedAt;
    private String createdBy;
    private String lastModifiedBy;

    public String getUsername() {
        return username;
    }

    public List<String> getRoles() {
        return roles;
    }

    private List<String> roles;
}