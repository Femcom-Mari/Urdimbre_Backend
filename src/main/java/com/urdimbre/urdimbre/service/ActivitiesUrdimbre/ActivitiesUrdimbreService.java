package com.urdimbre.urdimbre.service.ActivitiesUrdimbre;

import java.util.List;

import com.urdimbre.urdimbre.dto.ActivitiesUrdimbre.ActivitiesUrdimbreRequestDTO;
import com.urdimbre.urdimbre.dto.ActivitiesUrdimbre.ActivitiesUrdimbreResponseDTO;

public interface ActivitiesUrdimbreService {
    

    ActivitiesUrdimbreResponseDTO createActivitiesUrdimbre(ActivitiesUrdimbreRequestDTO activityUrdimbreDTO);
    
    List<ActivitiesUrdimbreResponseDTO> getActivitiesByCategory(String category);
}
