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

    @NotBlank(message = "(!) ERROR: This field cannot be empty")
    @Size(max = 30, message = "(!) ERROR: Maximum 30 characters allowed for title")
    @Pattern(regexp = "^[A-Za-z0-9ÁÉÍÓÚáéíóúñÑ.,:;!?()\"'\\-\\s]+$", message = "The title contains illegal characters")
    private String title;

    @NotNull(message = "(!) ERROR: The description field cannot be empty")
    @Size(max = 500, message = "(!) ERROR: Maximum 500 characters allowed in the field")
    @Pattern(regexp = "^[\\p{L}\\p{N}\\p{P}\\p{Zs}]{1,500}$", message = "The description contains invalid characters")
    private String description;

    @Future(message = "Date must be in the future")
    @NotNull(message = "(!) ERROR: The date field cannot be empty")
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate date;

    @NotNull(message = "(!) ERROR: You need to select a category")
    private CategoryEvents category;

    @Size(max = 255, message = "URL must not exceed 255 characters")
    @NotBlank(message = "(!) ERROR: The link cannot be blank")
    @Pattern(
    regexp = "^(https?://)(?!.*(script|data|javascript|onerror|onload|alert|eval|<|>)).{1,255}$",
    message = "(!) ERROR: The link must be a valid and safe URL"
    )
    private String link;

}
