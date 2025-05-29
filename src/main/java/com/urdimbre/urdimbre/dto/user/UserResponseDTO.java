package com.urdimbre.urdimbre.dto.user;

import java.util.List;

import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
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
    private String status;
    private String createdAt;
    private String updatedAt;
    private List<String> roles;
}