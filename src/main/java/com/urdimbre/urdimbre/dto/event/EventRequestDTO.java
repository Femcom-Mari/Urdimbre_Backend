package com.urdimbre.urdimbre.dto.event;

import java.time.LocalDate;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.urdimbre.urdimbre.model.CategoryEvents;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventRequestDTO {

    @NotBlank(message = "(!) ERROR: Este campo no puede estar vacío")
    @Size(max = 30, message = "(!) ERROR: Máximo 30 caracteres permitidos para el título")
    @Pattern(regexp = "^[A-Za-z0-9ÁÉÍÓÚáéíóúñÑ.,:;!?()\"'\\-\\s]+$", message = "(!) ERROR: El título contiene caracteres no permitidos")
    private String title;

    @NotNull(message = "(!) ERROR: El campo descripción no puede estar vacío")
    @Size(max = 500, message = "(!) ERROR: Máximo 500 caracteres permitidos para la descripción")
    @Pattern(regexp = "^[\\p{L}\\p{N}\\p{P}\\p{Zs}]{1,500}$", message = "(!) ERROR: La descripción contiene caracteres inválidos")
    private String description;

    @Future(message = "(!) ERROR: La fecha debe ser en el futuro")
    @NotNull(message = "(!) ERROR: El campo fecha no puede estar vacío")
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate date;

    @NotNull(message = "(!) ERROR: Debes seleccionar una categoría")
    private CategoryEvents category;

    @Size(max = 255, message = "(!) ERROR: La URL no debe superar los 255 caracteres")
    @NotBlank(message = "(!) ERROR: El enlace no puede estar en blanco")
    @Pattern(regexp = "^(https?://)(?!.*(script|data|javascript|onerror|onload|alert|eval|<|>)).{1,255}$", message = "(!) ERROR: El enlace debe ser una URL válida y segura")
    private String link;
}
