package com.urdimbre.urdimbre.dto.user;

import java.util.List;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateRolesRequestDTO {

    @NotNull(message = "La lista de roles no puede ser null")
    @NotEmpty(message = "Debe especificar al menos un rol")
    private List<String> roles;
}