package com.urdimbre.urdimbre.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
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
@Entity
@Table(name = "activities_urdimbre")
public class ActivitiesUrdimbre {

    @Id
    @SequenceGenerator(name = "activitiesUrdimbre_id_sequence", sequenceName = "activitiesUrdimbre_id_sequence", allocationSize = 1, initialValue = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "activitiesUrdimbre_id_sequence")
    private Integer id;

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
    @NotBlank
    private String date;
    
    //change the string 
    @Column
    @NotBlank
    private String startTime;

    @Column
    @NotBlank
    private String endTime;

    @Column
    @Min(value = 1)
    private Integer maxAttendees;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    @NotNull
    private Category category;


    //ralation whit user to catch the name of the coach


    //relation to attendees


 }
