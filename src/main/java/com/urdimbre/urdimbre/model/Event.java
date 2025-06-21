package com.urdimbre.urdimbre.model;

import java.time.LocalDate;
import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Event {

    @Id
    @SequenceGenerator(name = "event_id_sequence", sequenceName = "event_id_sequence", allocationSize = 1, initialValue = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "event_id_sequence")
    Long id;

    @Column
    @NotBlank
    @Size(max = 30)
    @Pattern(regexp = "^[A-Za-z0-9ÁÉÍÓÚáéíóúñÑ.,:;!?()\"'\\-\\s]+$", message = "The title contains illegal characters")
    private String title;

    @Column
    @NotBlank
    @Size(max = 500)
    @Pattern(regexp = "^[\\p{L}\\p{N}\\p{P}\\p{Zs}]{1,500}$", message = "The description contains invalid characters")
    private String description;

    @Column
    @NotNull(message = "(!) ERROR: The date field cannot be empty")
    @Future(message = "Date must be in the future")
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate date;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    @NotNull
    private CategoryEvents category;

    @Size(max = 255, message = "URL must not exceed 255 characters")
    @NotBlank(message = "(!) ERROR: The link cannot be blank")
    @Pattern(
    regexp = "^(https?://)(?!.*(script|data|javascript|onerror|onload|alert|eval|<|>)).{1,255}$",
    message = "(!) ERROR: The link must be a valid and safe URL"
    )
    private String link;

    @ManyToOne
    @JoinColumn(name = "creator_id", nullable = false)
    private User creator;


}
