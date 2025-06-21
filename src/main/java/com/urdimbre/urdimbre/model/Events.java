package com.urdimbre.urdimbre.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Events {

    @Id
    @SequenceGenerator(name = "event_id_sequence", sequenceName = "event_id_sequence", allocationSize = 1, initialValue = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "event_id_sequence")
    Long id;

    @Column
    @NotBlank
    @Size(max = 30)
    private String title;

    @Column
    @NotBlank
    @Size(max = 500)
    private String description;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    @NotNull
    private CategoryEvents category;

    @Size(max = 255, message = "URL must not exceed 255 characters")
    @NotBlank
    @Pattern(regexp = "^(https?://)?[\\w.-]+\\.[a-zA-Z]{2,}.*$", message = "URL1 format is invalid")
    private String link;


}
