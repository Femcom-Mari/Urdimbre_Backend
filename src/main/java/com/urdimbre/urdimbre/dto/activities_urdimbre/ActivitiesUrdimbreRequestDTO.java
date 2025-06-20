package com.urdimbre.urdimbre.dto.activities_urdimbre;

import com.urdimbre.urdimbre.model.Category;
import com.urdimbre.urdimbre.model.Language;

import jakarta.persistence.Column;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ActivitiesUrdimbreRequestDTO {

    private Integer id;

    @NotNull(message = "(!) ERROR: Debes seleccionar una categoría")
    private Category category;

    @NotNull(message = "(!) ERROR: El título no puede estar vacío")
    @NotBlank(message = "(!) ERROR: El título no puede estar vacío")
    @Size(max = 200, message = "(!) ERROR: El título no puede tener más de 200 caracteres")
    private String title;

    @NotBlank(message = "(!) ERROR: La descripción no puede estar vacía")
    @Size(max = 500, message = "(!) ERROR: Máximo 500 caracteres permitidos en la descripción")
    private String description;

    @NotNull(message = "(!) ERROR: El idioma no puede estar vacío")
    private Language language;

    @NotNull(message = "(!) ERROR: La fecha no puede estar vacía")
    private String date;

    @NotNull(message = "(!) ERROR: La hora de inicio no puede estar vacía")
    private String startTime;

    @NotNull(message = "(!) ERROR: La hora de fin no puede estar vacía")
    private String endTime;

    @Column
    @NotNull(message = "(!) ERROR: Debes especificar el número máximo de participantes")
    @Min(value = 1, message = "(!) ERROR: El número máximo de participantes debe ser al menos 1")
    private Integer maxAttendees;
}