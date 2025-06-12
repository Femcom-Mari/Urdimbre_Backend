package com.urdimbre.urdimbre.model;

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
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Attendance {

    @Id
    @SequenceGenerator(name = "attendance_id_sequence", sequenceName = "attendance_id_sequence", allocationSize = 1, initialValue = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "attendance_id_sequence")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "activities_id", nullable = false)
    private ActivitiesUrdimbre activitiesUrdimbre;


    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AttendanceStatus status = AttendanceStatus.CONFIRMED;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
}
