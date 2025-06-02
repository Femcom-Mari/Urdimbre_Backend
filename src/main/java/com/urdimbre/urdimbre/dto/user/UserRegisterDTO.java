package com.urdimbre.urdimbre.dto.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
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

    // ✅ NOMBRES SEPARADOS COMO REQUIERE EL FRONTEND
    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 50, message = "El nombre no puede tener más de 50 caracteres")
    @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\\s]+$", message = "El nombre solo puede contener letras y espacios")
    private String firstName;

    @NotBlank(message = "El apellido es obligatorio")
    @Size(max = 50, message = "El apellido no puede tener más de 50 caracteres")
    @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\\s]+$", message = "El apellido solo puede contener letras y espacios")
    private String lastName;

    @NotBlank(message = "Los pronombres son obligatorios")
    @Pattern(regexp = "^(Elle|Ella|El)$", message = "Los pronombres deben ser: Elle, Ella o El")
    private String pronouns;

    @NotBlank(message = "La contraseña es obligatoria")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$", message = "La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un símbolo (@$!%*?&)")
    private String password;

    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El formato del email no es válido")
    private String email;

    @NotBlank(message = "El código de invitación es obligatorio")
    private String inviteCode;

    // ✅ MÉTODO PARA COMBINAR NOMBRE Y APELLIDO
    public String getFullName() {
        if (firstName != null && lastName != null) {
            return (firstName.trim() + " " + lastName.trim()).trim();
        }
        return null;
    }

    // ✅ COMPATIBILIDAD CON CÓDIGO EXISTENTE
    public String getInvitationCode() {
        return inviteCode;
    }
}