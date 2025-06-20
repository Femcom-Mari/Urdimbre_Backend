package com.urdimbre.urdimbre.dto.user;

import java.util.Set;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserRequestDTO {

    private String username;
    private String password;

    @Email(message = "El formato del email no es válido")
    private String email;

    @Size(max = 100, message = "El nombre completo no puede exceder los 100 caracteres")
    private String fullName;

    @Size(max = 1000, message = "La biografía no puede exceder los 1000 caracteres")
    private String biography;

    @Size(max = 100, message = "La ubicación no puede exceder los 100 caracteres")
    private String location;

    private String profileImageUrl;

    private Set<String> pronouns;

    // ✅ CÓDIGO DE INVITACIÓN OPCIONAL - Solo obligatorio para registro desde front
    // NO obligatorio cuando ADMIN crea usuarios directamente
    private String inviteCode;

    public boolean isLoginRequest() {
        return username != null && password != null &&
                email == null && fullName == null;
    }

    public boolean isUpdateRequest() {
        return username == null && password == null &&
                (email != null || fullName != null || biography != null ||
                        location != null || profileImageUrl != null || pronouns != null);
    }

    public boolean isCreateRequest() {
        return username != null && password != null && email != null;
    }
}