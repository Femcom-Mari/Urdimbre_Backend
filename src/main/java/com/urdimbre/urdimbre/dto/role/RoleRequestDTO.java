package com.urdimbre.urdimbre.dto.role;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RoleRequestDTO {

    private Long id;

    @NotBlank(message = "El nombre del rol es obligatorio")
    @Size(min = 3, max = 60, message = "El nombre del rol debe tener entre 3 y 60 caracteres")
    @Pattern(regexp = "^ROLE_[A-Z_]+$", message = "El nombre del rol debe seguir el formato ROLE_NOMBRE (ej: ROLE_USER, ROLE_ADMIN)")
    private String name;

    @Size(max = 200, message = "La descripción del rol no puede exceder los 200 caracteres")
    private String description;
}