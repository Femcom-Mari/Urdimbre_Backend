package com.urdimbre.urdimbre.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;



@Data
@Entity
@Table(name = "activities_schedule")
public class activitiesScheduleUrdimbre {

    @Id
    @SequenceGenerator(name = "activitiesSchedule_id_sequence", sequenceName = "activitiesSchedule_id_sequence", allocationSize = 1, initialValue = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "activitiesSchedule_id_sequence")
    private Integer id;



    //relation with sub categories
    @Column
    @NotBlank(message = "(!) ERROR: The name of the activity field cannot be empty")
    @Size(max = 50, message = "(!) ERROR: Maximun 50 characters allowed in this field")
    private String activityname;

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


    //ralation whit user to catch the name of the coach


    //relation to attendees


 }
