package com.urdimbre.urdimbre.service.activities_urdimbre;

import java.time.LocalDate;
import java.util.List;

import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreRequestDTO;
import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreResponseDTO;
import com.urdimbre.urdimbre.model.Language;

public interface ActivitiesUrdimbreService {

    ActivitiesUrdimbreResponseDTO createActivitiesUrdimbre(ActivitiesUrdimbreRequestDTO activityUrdimbreDTO,
            String creatorUsername);

    List<ActivitiesUrdimbreResponseDTO> getActivitiesByCategory(String category);

    List<ActivitiesUrdimbreResponseDTO> getActivitiesByDate(LocalDate date);

    List<ActivitiesUrdimbreResponseDTO> getActivitiesByLanguage(Language language);

    List<ActivitiesUrdimbreResponseDTO> getUpcomingActivities();

    List<ActivitiesUrdimbreResponseDTO> searchActivitiesByTitle(String title);

    ActivitiesUrdimbreResponseDTO getActivityById(Long activityId);

    void deleteActivity(Long activityId);

    ActivitiesUrdimbreResponseDTO updateActivity(Long activityId, ActivitiesUrdimbreRequestDTO dto);

    List<ActivitiesUrdimbreResponseDTO> getUpcomingActivities(int days, int page, int size);

    List<ActivitiesUrdimbreResponseDTO> getAllActivities(int page, int size);
}
