package com.urdimbre.urdimbre.dto.invite;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BulkInviteCodeRequestDTO {

    @NotNull(message = "La cantidad es obligatoria")
    @Min(value = 1, message = "Mínimo 1 código")
    @Max(value = 50, message = "Máximo 50 códigos por operación")
    private Integer quantity;

    @Size(max = 255, message = "La descripción no puede exceder 255 caracteres")
    private String description;

    @NotNull(message = "La duración en horas es obligatoria")
    @Min(value = 1, message = "La duración mínima es 1 hora")
    @Max(value = 168, message = "La duración máxima es 168 horas (7 días)")
    private Integer durationHours;

    @Min(value = 1, message = "El máximo de usos debe ser al menos 1")
    @Max(value = 1000, message = "El máximo de usos no puede exceder 1000")
    private Integer maxUses;

    @Size(max = 20, message = "El prefijo no puede exceder 20 caracteres")
    private String prefix;
}