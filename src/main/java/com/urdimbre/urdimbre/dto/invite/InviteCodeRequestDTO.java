package com.urdimbre.urdimbre.dto.invite;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

// ================================
// REQUEST DTO
// ================================
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InviteCodeRequestDTO {

    @Size(max = 255, message = "La descripción no puede exceder 255 caracteres")
    private String description;

    @NotNull(message = "La duración en horas es obligatoria")
    @Min(value = 1, message = "La duración mínima es 1 hora")
    @Max(value = 168, message = "La duración máxima es 168 horas (7 días)")
    private Integer durationHours;

    @Min(value = 1, message = "El máximo de usos debe ser al menos 1")
    @Max(value = 1000, message = "El máximo de usos no puede exceder 1000")
    private Integer maxUses;

    @Size(max = 50, message = "El código personalizado no puede exceder 50 caracteres")
    private String customCode; // Opcional: código personalizado
}
