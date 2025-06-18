package com.urdimbre.urdimbre.dto.user;

import java.util.Set;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRegisterDTO {

    @NotBlank(message = "El nombre de usuarie es obligatorio")
    @Size(min = 3, max = 20, message = "El nombre de usuarie debe tener entre 3 y 20 caracteres")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "El nombre de usuarie solo puede contener letras, números, guiones y guiones bajos")
    private String username;

    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 50, message = "El nombre no puede tener más de 50 caracteres")
    @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\\s]+$", message = "El nombre solo puede contener letras y espacios")
    private String firstName;

    @NotBlank(message = "El apellido es obligatorio")
    @Size(max = 50, message = "El apellido no puede tener más de 50 caracteres")
    @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\\s]+$", message = "El apellido solo puede contener letras y espacios")
    private String lastName;

    @NotEmpty(message = "Debe seleccionar al menos un pronombre")
    private Set<String> pronouns;

    @NotBlank(message = "La contraseña es obligatoria")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$", message = "La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un símbolo (@$!%*?&)")
    private String password;

    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El formato del email no es válido")
    private String email;

    @NotBlank(message = "El código de invitación es obligatorio")
    private String inviteCode;

    public String getFullName() {
        if (firstName != null && lastName != null) {
            return (firstName.trim() + " " + lastName.trim()).trim();
        }
        return null;
    }

    public String getInvitationCode() {
        return inviteCode;
    }
}