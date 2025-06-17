package com.urdimbre.urdimbre.service.activitiesUrdimbre;

import java.time.LocalDate;
import java.util.List;

import com.urdimbre.urdimbre.dto.activitiesUrdimbre.ActivitiesUrdimbreRequestDTO;
import com.urdimbre.urdimbre.dto.activitiesUrdimbre.ActivitiesUrdimbreResponseDTO;
import com.urdimbre.urdimbre.dto.attendance.AttendanceResponseDTO;
public interface ActivitiesUrdimbreService {
    

    ActivitiesUrdimbreResponseDTO createActivitiesUrdimbre(ActivitiesUrdimbreRequestDTO activityUrdimbreDTO);
    
    List<ActivitiesUrdimbreResponseDTO> getActivitiesByCategory(String category);

    List<ActivitiesUrdimbreResponseDTO> getActivitiesByDate(LocalDate date);

    List<AttendanceResponseDTO> getUserAttendances(Long userId);

    void deleteActivity(Long id);

    ActivitiesUrdimbreResponseDTO updateActivities (ActivitiesUrdimbreRequestDTO activitiesUrdimbreDTO);




}
