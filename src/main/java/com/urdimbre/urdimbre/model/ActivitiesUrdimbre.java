package com.urdimbre.urdimbre.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;



@Data
@Entity
@Table(name = "activities_urdimbre")
public class ActivitiesUrdimbre {

    @Id
    @SequenceGenerator(name = "activitiesUrdimbre_id_sequence", sequenceName = "activitiesUrdimbre_id_sequence", allocationSize = 1, initialValue = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "activitiesUrdimbre_id_sequence")
    private Integer id;



    @Column
    @NotBlank(message = "(!) ERROR: The description field cannot be empty")
    @Size(max = 500, message = "(!) ERROR: Maximun 500 characters allowed in the field")
    private String description;

    @Column
    @NotBlank(message = "(!) ERROR: el campo del idioma no puede estar vacío")
    @Size(max = 500, message = "(!) ERROR: el campo del título no puede tener más de 500 caracteres")
    private String idioma;
    //Usar ENUM

    @Column
    @NotBlank(message = "(!) ERROR: The date field cannot be empty")
    private String date;

    @Column
    @NotBlank(message = "(!) ERROR: The time field cannot be empty")
    private String time;


    @Column
    @Min(value = 1, message = "(!) ERROR: el campo del máximo de participantes debe tener un valor mínimo de 1")
    private Integer maxAttendees;


    @ManyToOne
    @JoinColumn(name = "subActivity_id", nullable = false)
    private Activities Activities;


    //ralation whit user to catch the name of the coach


    //relation to attendees


 }
