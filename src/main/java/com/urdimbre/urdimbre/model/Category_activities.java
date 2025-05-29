package com.urdimbre.urdimbre.model;

import java.util.List;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;


@Entity
@Table(name="category_activities")
@Data
public class Category_activities {
    
    @Id
    @SequenceGenerator(name ="activities_id_sequence", sequenceName = "activities_id_sequence", allocationSize = 1, initialValue = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator ="activities_id_sequence")
    private Integer id;

    @Column
    @NotBlank(message = "(!) ERROR: The name of the category field cannot be empty")
    @Size(max = 50, message = "(!) ERROR: Maximun 50 characters allowed in this field")
    private String categoryName;


    @OneToMany(mappedBy = "category_activities", cascade = CascadeType.ALL)
    private List<ActivitiesUrdimbre> activitiesUrdimbre;
    

}
