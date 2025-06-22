package com.urdimbre.urdimbre.model;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonFormat;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
@Table(name = "activities_urdimbre")
public class ActivitiesUrdimbre {

    @Id
    @SequenceGenerator(name = "activitiesUrdimbre_id_sequence", sequenceName = "activitiesUrdimbre_id_sequence", allocationSize = 1, initialValue = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "activitiesUrdimbre_id_sequence")
    private Long id;

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
    private Language language;

    @Column
    @NotNull
    @Future
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate date;

    @Column
    @NotNull
    private LocalTime startTime;

    @Column
    @NotNull
    private LocalTime endTime;

    @Column
    @Min(value = 1)
    private Long maxAttendees;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    @NotNull
    private Category category;

    @OneToMany(mappedBy = "activityId", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Attendance> attendances;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "creator_id")
    private User creator;

    @Column(name = "created_at", nullable = false, updatable = false)
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm")
    private LocalDateTime createdAt;

}
