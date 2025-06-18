package com.urdimbre.urdimbre.service.activities_urdimbre;

import java.time.LocalDate;
import java.util.List;

import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreRequestDTO;
import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreResponseDTO;
import com.urdimbre.urdimbre.dto.attendance.AttendanceResponseDTO;

public interface ActivitiesUrdimbreService {

    ActivitiesUrdimbreResponseDTO createActivitiesUrdimbre(ActivitiesUrdimbreRequestDTO activityUrdimbreDTO);

    List<ActivitiesUrdimbreResponseDTO> getActivitiesByCategory(String category);

    List<ActivitiesUrdimbreResponseDTO> getActivitiesByDate(LocalDate date);

    List<AttendanceResponseDTO> getUserAttendances(Long userId);

    void deleteActivity(Long id);

    ActivitiesUrdimbreResponseDTO updateActivities(ActivitiesUrdimbreRequestDTO activitiesUrdimbreDTO);

}
