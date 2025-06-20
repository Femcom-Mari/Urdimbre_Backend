package com.urdimbre.urdimbre.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Data
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ForgotPasswordResponseDTO {
    private boolean success;
    private String message;

    // ✅ Métodos de utilidad
    public static ForgotPasswordResponseDTO success(String message) {
        return ForgotPasswordResponseDTO.builder()
                .success(true)
                .message(message)
                .build();
    }

    public static ForgotPasswordResponseDTO error(String message) {
        return ForgotPasswordResponseDTO.builder()
                .success(false)
                .message(message)
                .build();
    }

    public static ForgotPasswordResponseDTO emailNotFound() {
        return ForgotPasswordResponseDTO.builder()
                .success(false)
                .message("No encontramos una cuenta con ese email")
                .build();
    }

    public static ForgotPasswordResponseDTO emailSent() {
        return ForgotPasswordResponseDTO.builder()
                .success(true)
                .message("Enlace de recuperación enviado al email")
                .build();
    }
}