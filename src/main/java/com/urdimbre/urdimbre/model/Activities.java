package com.urdimbre.urdimbre.model;

import com.fasterxml.jackson.annotation.JsonBackReference;


import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Entity
@Table(name="activities")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Activities {

    @Id
    @SequenceGenerator(name ="subActivities_id_sequence", sequenceName = "subActivities_id_sequence", allocationSize = 1, initialValue = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator ="subActivities_id_sequence")
    private Integer id;

    @Column
    @NotBlank(message = "(!) ERROR: The name of the activity field cannot be empty")
    @Size(max = 50, message = "(!) ERROR: Maximun 50 characters allowed in this field")
    private String activity;
    
    @ManyToOne
    @JsonBackReference
    @JoinColumn(name = "id_catedory_activity", nullable = false)
    private CategoryActivities categoryActivities;



    // @OneToMany(mappedBy = "activity", cascade = CascadeType.ALL)
    // private List<ActivitiesUrdimbre> activitiesUrdimbre = new ArrayList<>();
}
