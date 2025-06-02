package com.urdimbre.urdimbre.dto.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserRequestDTO {

    @NotBlank(message = "Invitation code is required")
    private String invitationCode;

    @NotBlank(message = "First name is required")
    @Size(max = 50, message = "First name must not exceed 50 characters")
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(max = 50, message = "Last name must not exceed 50 characters")
    private String lastName;

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Email format is invalid")
    private String email;

    @Size(min = 6, max = 40, message = "Password must be between 6 and 40 characters")
    private String password;

    @Size(max = 1000, message = "Biography must not exceed 1000 characters")
    private String biography;

    @Size(max = 100, message = "Location must not exceed 100 characters")
    private String location;

    private String profileImageUrl;

    private String userStatus;

    @NotBlank(message = "Pronouns are required")
    private String pronouns; // SHE, HE, THEY

    // Utility methods for request type detection (opcional)
    public boolean isLoginRequest() {
        return username != null && password != null && email == null;
    }

    public boolean isRegistrationRequest() {
        return username != null && password != null && email != null;
    }

    public boolean isUpdateRequest() {
        return username != null && password == null && email != null;
    }
}