package com.urdimbre.urdimbre.service.ActivitiesUrdimbre;

import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.dto.ActivitiesUrdimbre.ActivitiesUrdimbreRequestDTO;
import com.urdimbre.urdimbre.dto.ActivitiesUrdimbre.ActivitiesUrdimbreResponseDTO;
import com.urdimbre.urdimbre.model.ActivitiesUrdimbre;
import com.urdimbre.urdimbre.repository.ActivitiesUrdimbreRepository;

import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;

@Service
@Transactional
@AllArgsConstructor
public class ActivitiesUrdimbreServicelmpl implements ActivitiesUrdimbreService {

    private ActivitiesUrdimbreRepository activitiesUrdimbreRepository;

    @Override
    public ActivitiesUrdimbreResponseDTO createActivitiesUrdimbre(ActivitiesUrdimbreRequestDTO dto) {
    ActivitiesUrdimbre activity = new ActivitiesUrdimbre();
    activity.setCategory(dto.getCategory());
    activity.setTitle(dto.getTitle());
    activity.setDescription(dto.getDescription());
    activity.setLanguage(dto.getLanguage());
    activity.setDate(dto.getDate());
    activity.setStartTime(dto.getStartTime());
    activity.setEndTime(dto.getEndTime());
    activity.setMaxAttendees(dto.getMaxAttendees());
    
    ActivitiesUrdimbre saved = activitiesUrdimbreRepository.save(activity);

    ActivitiesUrdimbreResponseDTO response = ActivitiesUrdimbreResponseDTO.builder()
        .category(saved.getCategory())
        .title(dto.getTitle())
        .description(saved.getDescription())
        .language(saved.getLanguage())
        .date(saved.getDate())
        .startTime(saved.getStartTime())
        .endTime(saved.getEndTime())
        .maxAttendees(saved.getMaxAttendees())
        .build();

    return response;

}



 }