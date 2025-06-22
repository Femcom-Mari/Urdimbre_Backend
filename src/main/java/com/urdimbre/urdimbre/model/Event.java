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
    @Pattern(regexp = "^[A-Za-z0-9ÁÉÍÓÚáéíóúñÑ.,:;!?()\"'\\-\\s]+$")
    private String title;

    @Column
    @NotBlank
    @Size(max = 500)
    @Pattern(regexp = "^[\\p{L}\\p{N}\\p{P}\\p{Zs}]{1,500}$")
    private String description;

    @Column
    @NotNull
    @Future
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate date;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    @NotNull
    private CategoryEvents category;

    @Size
    @NotBlank
    @Pattern(
    regexp = "^(https?://)(?!.*(script|data|javascript|onerror|onload|alert|eval|<|>)).{1,255}$")
    private String link;

    @ManyToOne
    @JoinColumn(name = "creator_id", nullable = false)
    private User creator;


}
