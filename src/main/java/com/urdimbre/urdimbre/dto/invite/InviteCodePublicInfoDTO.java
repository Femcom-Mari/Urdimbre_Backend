package com.urdimbre.urdimbre.dto.invite;

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
public class InviteCodePublicInfoDTO {
    private boolean valid;
    private String message;

    // ✅ Métodos de utilidad
    public static InviteCodePublicInfoDTO valid(String message) {
        return InviteCodePublicInfoDTO.builder()
                .valid(true)
                .message(message != null ? message : "Código válido")
                .build();
    }

    public static InviteCodePublicInfoDTO invalid(String message) {
        return InviteCodePublicInfoDTO.builder()
                .valid(false)
                .message(message != null ? message : "Código inválido")
                .build();
    }

    public static InviteCodePublicInfoDTO expired() {
        return InviteCodePublicInfoDTO.builder()
                .valid(false)
                .message("Código expirado")
                .build();
    }

    public static InviteCodePublicInfoDTO maxUsesReached() {
        return InviteCodePublicInfoDTO.builder()
                .valid(false)
                .message("Código agotado (máximo de usos alcanzado)")
                .build();
    }

    public static InviteCodePublicInfoDTO notFound() {
        return InviteCodePublicInfoDTO.builder()
                .valid(false)
                .message("Código no encontrado")
                .build();
    }

    public static InviteCodePublicInfoDTO revoked() {
        return InviteCodePublicInfoDTO.builder()
                .valid(false)
                .message("Código revocado")
                .build();
    }
}