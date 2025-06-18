package com.urdimbre.urdimbre.service.activities_urdimbre;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;

import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreRequestDTO;
import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreResponseDTO;
import com.urdimbre.urdimbre.dto.attendance.AttendanceResponseDTO;
import com.urdimbre.urdimbre.exception.EntityNotFoundException;
import com.urdimbre.urdimbre.model.ActivitiesUrdimbre;
import com.urdimbre.urdimbre.model.Attendance;
import com.urdimbre.urdimbre.model.Category;
import com.urdimbre.urdimbre.repository.ActivitiesUrdimbreRepository;
import com.urdimbre.urdimbre.repository.AttendanceRepository;

import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;

@Service
@Transactional
@AllArgsConstructor
public class ActivitiesUrdimbreServiceImpl implements ActivitiesUrdimbreService {

    private final ActivitiesUrdimbreRepository activitiesUrdimbreRepository;
    private final AttendanceRepository attendanceRepository;

    @Override
    public ActivitiesUrdimbreResponseDTO createActivitiesUrdimbre(ActivitiesUrdimbreRequestDTO dto) {
        ActivitiesUrdimbre activity = new ActivitiesUrdimbre();
        populateActivitiesFromDto(activity, dto);
        ActivitiesUrdimbre saved = activitiesUrdimbreRepository.save(activity);

        return convertToDto(saved);
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

    @Override
    public List<AttendanceResponseDTO> getUserAttendances(Long userId) {
        return attendanceRepository.findByUserId(userId).stream()
                .map(this::convertToAttendanceDto)
                .toList();
    }

    @Override
    public void deleteActivity(Long id) {
        ActivitiesUrdimbre activity = activitiesUrdimbreRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Activity not found"));

        activitiesUrdimbreRepository.deleteById(activity.getId());
    }

    @Override
    public ActivitiesUrdimbreResponseDTO updateActivities(ActivitiesUrdimbreRequestDTO dto) {
        ActivitiesUrdimbre activity = activitiesUrdimbreRepository.findById(dto.getId())
                .orElseThrow(() -> new EntityNotFoundException("Activity not found"));
        populateActivitiesFromDto(activity, dto);
        ActivitiesUrdimbre updated = activitiesUrdimbreRepository.save(activity);
        return convertToDto(updated);
    }

    private void populateActivitiesFromDto(ActivitiesUrdimbre activity, ActivitiesUrdimbreRequestDTO dto) {
        activity.setCategory(dto.getCategory());
        activity.setTitle(dto.getTitle());
        activity.setDescription(dto.getDescription());
        activity.setLanguage(dto.getLanguage());
        activity.setDate(LocalDate.parse(dto.getDate()));
        activity.setStartTime(LocalTime.parse(dto.getStartTime()));
        activity.setEndTime(LocalTime.parse(dto.getEndTime()));
        activity.setMaxAttendees(dto.getMaxAttendees() != null ? dto.getMaxAttendees().longValue() : null);
    }

    private ActivitiesUrdimbreResponseDTO convertToDto(ActivitiesUrdimbre activity) {
        Integer currentAttendees = attendanceRepository.countByActivityId(activity);

        return ActivitiesUrdimbreResponseDTO.builder()
                .id(activity.getId())
                .category(activity.getCategory())
                .title(activity.getTitle())
                .description(activity.getDescription())
                .language(activity.getLanguage())
                .date(activity.getDate())
                .startTime(activity.getStartTime())
                .endTime(activity.getEndTime())
                .maxAttendees(activity.getMaxAttendees() != null ? activity.getMaxAttendees().intValue() : null)
                .currentAttendees(currentAttendees)
                .build();
    }

    private AttendanceResponseDTO convertToAttendanceDto(Attendance attendance) {
        return new AttendanceResponseDTO(
                attendance.getId(),
                attendance.getUser().getId(),
                attendance.getUser().getUsername(),
                attendance.getActivityId().getId(),
                attendance.getActivityId().getTitle(),
                attendance.getStatus());
    }
}
