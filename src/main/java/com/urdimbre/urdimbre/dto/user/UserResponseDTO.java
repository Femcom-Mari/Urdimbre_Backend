package com.urdimbre.urdimbre.dto.user;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserResponseDTO {
    private Long id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private String fullName; // opcional, puedes construirlo en el servicio
    private String biography;
    private String location;
    private String profileImageUrl;
    private String userStatus;
    private String pronouns; // SHE, HE, THEY
    private String invitationCode;
    private String createdAt;
    private String updatedAt;
    private List<String> roles;
}