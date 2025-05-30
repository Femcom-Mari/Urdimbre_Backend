package com.urdimbre.urdimbre.dto.ActivitiesUrdimbre;

import java.time.LocalDateTime;

import com.urdimbre.urdimbre.model.Language;

import jakarta.persistence.Column;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.Future;
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

    @NotNull(message = "(!) ERROR: You need to select a category")
    private Integer categoryId;

    @NotNull(message = "(!) ERROR: You need to select a activity")
    private Integer activityId;

    @NotBlank(message = "(!) ERROR: The description field cannot be empty")
    @Size(max = 500, message = "(!) ERROR: Maximun 500 characters allowed in the field")
    private String description;


    @NotNull(message = "(!) ERROR: The language field cannot be empty")
    private Language language;

    

    @NotNull(message = "(!) ERROR: The date field cannot be empty")
    private String date;


    @NotNull(message = "La fecha y hora de inicio es obligatoria")
    @Future(message = "La fecha y hora de inicio debe ser futura")
    private LocalDateTime startTime;

    @NotNull(message = "La fecha y hora de finalización es obligatoria")
    @Future(message = "La fecha y hora de finalización debe ser futura")
    private LocalDateTime endTime;


    @Column
    @NotNull
    @Min(value = 1, message = "(!) ERROR: The maximum particioants field must have a minimim value of 1")
    private Integer maxAttendees;

}
