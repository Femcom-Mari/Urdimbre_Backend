package com.urdimbre.urdimbre.dto.activities_urdimbre;

import com.urdimbre.urdimbre.model.Category;
import com.urdimbre.urdimbre.model.Language;

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

    private Long id; // ✅ Cambiado a Long para consistencia

    @NotNull(message = "(!) ERROR: You need to select a category")
    private Category category;

    @NotBlank(message = "(!) ERROR: This field cannot be empty")
    @Size(max = 30, message = "(!) ERROR: Maximum 30 characters allowed for title")
    private String title;

    @NotBlank(message = "(!) ERROR: The description field cannot be empty")
    @Size(max = 500, message = "(!) ERROR: Maximum 500 characters allowed in the field")
    private String description;

    @NotNull(message = "(!) ERROR: The language field cannot be empty")
    private Language language;

    @NotBlank(message = "(!) ERROR: The date field cannot be empty")
    private String date;

    @NotBlank(message = "(!) ERROR: Start Time cannot be empty")
    private String startTime;

    @NotBlank(message = "(!) ERROR: End Time cannot be empty")
    private String endTime;

    @NotNull(message = "(!) ERROR: Maximum attendees is required")
    @Min(value = 1, message = "(!) ERROR: The maximum participants field must have a minimum value of 1")
    private Integer maxAttendees;
}
