package com.urdimbre.urdimbre.repository;


import java.time.LocalDate;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.urdimbre.urdimbre.model.ActivitiesUrdimbre;
import com.urdimbre.urdimbre.model.Attendance;
import com.urdimbre.urdimbre.model.AttendanceStatus;
import com.urdimbre.urdimbre.model.Category;

@Repository
public interface ActivitiesUrdimbreRepository extends JpaRepository<ActivitiesUrdimbre, Long> {


    List<ActivitiesUrdimbre> findAllByCategory(Category category);
    List<ActivitiesUrdimbre> findAllByDate(LocalDate date);
    List<Attendance> findByActivityIdAndStatus(Long activityId, AttendanceStatus status);

    
}