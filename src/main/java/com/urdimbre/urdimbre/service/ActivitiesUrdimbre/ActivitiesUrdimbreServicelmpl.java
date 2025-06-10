package com.urdimbre.urdimbre.service.ActivitiesUrdimbre;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.dto.ActivitiesUrdimbre.ActivitiesUrdimbreRequestDTO;
import com.urdimbre.urdimbre.dto.ActivitiesUrdimbre.ActivitiesUrdimbreResponseDTO;
import com.urdimbre.urdimbre.model.ActivitiesUrdimbre;
import com.urdimbre.urdimbre.model.Category;
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
        activity.setDate(LocalDate.parse(dto.getDate()));
        activity.setStartTime(LocalTime.parse(dto.getStartTime()));
        activity.setEndTime(LocalTime.parse(dto.getEndTime()));
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

    @Override
    public List<ActivitiesUrdimbreResponseDTO> getActivitiesByCategory(String categoryStr) {
        Category category = Category.valueOf(categoryStr.toUpperCase());

        return activitiesUrdimbreRepository.findAllByCategory(category)
                .stream()
                .map(this::convertToDto)
                .toList();
    }

    @Override
    public List<ActivitiesUrdimbreResponseDTO> getActivitiesByDate(LocalDate date) {
        return activitiesUrdimbreRepository.findAllByDate(date)
                .stream()
                .map(this::convertToDto)
                .toList();
    }

    private ActivitiesUrdimbreResponseDTO convertToDto(ActivitiesUrdimbre activities) {
        return new ActivitiesUrdimbreResponseDTO(
                activities.getCategory(),
                activities.getTitle(),
                activities.getDescription(),
                activities.getLanguage(),
                activities.getDate(),
                activities.getStartTime(),
                activities.getEndTime(),
                activities.getMaxAttendees());
    }
}
