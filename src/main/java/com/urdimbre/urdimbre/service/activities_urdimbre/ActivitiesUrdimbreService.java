package com.urdimbre.urdimbre.service.activities_urdimbre;

import java.time.LocalDate;
import java.util.List;

import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreRequestDTO;
import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreResponseDTO;

public interface ActivitiesUrdimbreService {

    ActivitiesUrdimbreResponseDTO createActivitiesUrdimbre(ActivitiesUrdimbreRequestDTO activityUrdimbreDTO);

    List<ActivitiesUrdimbreResponseDTO> getActivitiesByCategory(String category);

    List<ActivitiesUrdimbreResponseDTO> getActivitiesByDate(LocalDate date);

}
