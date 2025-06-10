package com.urdimbre.urdimbre.service.activitiesUrdimbre;

import java.time.LocalDate;
import java.util.List;

import com.urdimbre.urdimbre.dto.activitiesUrdimbre.ActivitiesUrdimbreRequestDTO;
import com.urdimbre.urdimbre.dto.activitiesUrdimbre.ActivitiesUrdimbreResponseDTO;

public interface ActivitiesUrdimbreService {
    

    ActivitiesUrdimbreResponseDTO createActivitiesUrdimbre(ActivitiesUrdimbreRequestDTO activityUrdimbreDTO);
    
    List<ActivitiesUrdimbreResponseDTO> getActivitiesByCategory(String category);

    List<ActivitiesUrdimbreResponseDTO> getActivitiesByDate(LocalDate date);

}
