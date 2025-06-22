package com.urdimbre.urdimbre.service.activities_urdimbre;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreRequestDTO;
import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreResponseDTO;
import com.urdimbre.urdimbre.exception.ActivityNotFoundException;
import com.urdimbre.urdimbre.exception.ResourceNotFoundException;
import com.urdimbre.urdimbre.model.ActivitiesUrdimbre;
import com.urdimbre.urdimbre.model.Category;
import com.urdimbre.urdimbre.model.Language;
import com.urdimbre.urdimbre.model.User;
import com.urdimbre.urdimbre.repository.ActivitiesUrdimbreRepository;
import com.urdimbre.urdimbre.repository.AttendanceRepository;
import com.urdimbre.urdimbre.repository.UserRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class ActivitiesUrdimbreServiceImpl implements ActivitiesUrdimbreService {

        // ✅ Constante para evitar duplicación de strings
        private static final String ACTIVITY_NOT_FOUND_MESSAGE = "Actividad no encontrada con id: ";

        private final ActivitiesUrdimbreRepository activitiesUrdimbreRepository;
        private final AttendanceRepository attendanceRepository;
        private final UserRepository userRepository;


        @Override
        public ActivitiesUrdimbreResponseDTO createActivitiesUrdimbre(ActivitiesUrdimbreRequestDTO dto,String creatorUsername) {
                log.info("🎨 Creando nueva actividad: {}", dto.getTitle());
                User createdBy = getUser(creatorUsername);
                ActivitiesUrdimbre activity = mapToEntity(dto, createdBy);
                ActivitiesUrdimbre saved = activitiesUrdimbreRepository.save(activity);
                log.info("✅ Actividad creada exitosamente - ID: {}", saved.getId());
                return convertToDto(saved); 
        }

        @Override
        public List<ActivitiesUrdimbreResponseDTO> getAllActivities(int page, int size) {
                log.info("📋 Obteniendo todas las actividades (página: {}, tamaño: {})", page, size);

                Pageable pageable = PageRequest.of(page, size,
                                Sort.by("date").descending().and(Sort.by("startTime").descending()));
                Page<ActivitiesUrdimbre> activitiesPage = activitiesUrdimbreRepository.findAll(pageable);

                return activitiesPage.getContent().stream()
                                .map(this::convertToDto)
                                .toList();
        }

        @Override
        public List<ActivitiesUrdimbreResponseDTO> getActivitiesByCategory(String categoryStr) {
                log.info("📂 Buscando actividades por categoría: {}", categoryStr);
                Category category = Category.valueOf(categoryStr.toUpperCase());

                return activitiesUrdimbreRepository.findAllByCategoryOrderByDateAsc(category)
                                .stream()
                                .map(this::convertToDto)
                                .toList();
        }

        @Override
        public List<ActivitiesUrdimbreResponseDTO> getActivitiesByDate(LocalDate date) {
                log.info("📅 Buscando actividades por fecha: {}", date);
                return activitiesUrdimbreRepository.findByDate(date)
                                .stream()
                                .map(this::convertToDto)
                                .toList();
        }

        @Override
        public List<ActivitiesUrdimbreResponseDTO> getActivitiesByLanguage(Language language) {
                log.info("🌐 Buscando actividades por idioma: {}", language);
                return activitiesUrdimbreRepository.findAllByLanguage(language)
                                .stream()
                                .map(this::convertToDto)
                                .toList();
        }

        // Método sin parámetros requerido por la interfaz
        @Override
        public List<ActivitiesUrdimbreResponseDTO> getUpcomingActivities() {
                log.info("🔮 Obteniendo actividades futuras (sin parámetros)");
                LocalDate today = LocalDate.now();
                return activitiesUrdimbreRepository.findAllByDateGreaterThanEqual(today)
                                .stream()
                                .map(this::convertToDto)
                                .toList();
        }

        // Método con parámetros de paginación (sobrecarga)
        @Override
        public List<ActivitiesUrdimbreResponseDTO> getUpcomingActivities(int days, int page, int size) {
                log.info("🔮 Obteniendo actividades futuras para {} días (página: {}, tamaño: {})", days, page, size);

                LocalDate today = LocalDate.now();
                LocalDate futureDate = today.plusDays(days);

                Pageable pageable = PageRequest.of(page, size,
                                Sort.by("date").ascending().and(Sort.by("startTime").ascending()));

                Page<ActivitiesUrdimbre> activitiesPage = activitiesUrdimbreRepository
                                .findByDateBetween(today, futureDate, pageable);

                return activitiesPage.getContent().stream()
                                .map(this::convertToDto)
                                .toList();
        }

        @Override
        public List<ActivitiesUrdimbreResponseDTO> searchActivitiesByTitle(String title) {
                log.info("🔍 Buscando actividades por título: {}", title);
                return activitiesUrdimbreRepository.findAllByTitleContainingIgnoreCase(title)
                                .stream()
                                .map(this::convertToDto)
                                .toList();
        }

        @Override
        public ActivitiesUrdimbreResponseDTO getActivityById(Long activityId) {
                log.info("🎯 Obteniendo actividad por ID: {}", activityId);
                ActivitiesUrdimbre activity = activitiesUrdimbreRepository.findById(activityId)
                                .orElseThrow(() -> new ActivityNotFoundException(
                                                ACTIVITY_NOT_FOUND_MESSAGE + activityId));

                return convertToDto(activity);
        }

        @Override
        public void deleteActivity(Long activityId) {
                log.info("🗑️ Eliminando actividad: {}", activityId);

                ActivitiesUrdimbre activity = activitiesUrdimbreRepository.findById(activityId)
                                .orElseThrow(() -> new ActivityNotFoundException(
                                                ACTIVITY_NOT_FOUND_MESSAGE + activityId));

                // Eliminar asistencias relacionadas primero
                attendanceRepository.deleteByActivityId_Id(activityId);

                // Eliminar la actividad
                activitiesUrdimbreRepository.delete(activity);

                log.info("✅ Actividad eliminada exitosamente");
        }

        @Override
        public ActivitiesUrdimbreResponseDTO updateActivity(Long activityId, ActivitiesUrdimbreRequestDTO dto) {
                log.info("📝 Actualizando actividad: {}", activityId);

                ActivitiesUrdimbre activity = activitiesUrdimbreRepository.findById(activityId)
                                .orElseThrow(() -> new ActivityNotFoundException(
                                                ACTIVITY_NOT_FOUND_MESSAGE + activityId));

                updateEntityFromDTO(activity, dto);
                
                ActivitiesUrdimbre saved = activitiesUrdimbreRepository.save(activity);
                log.info("✅ Actividad actualizada exitosamente");

                return convertToDto(saved);
        }








    private User getUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "Username", username));
    }

        private ActivitiesUrdimbre mapToEntity(ActivitiesUrdimbreRequestDTO dto, User creator) {
    return ActivitiesUrdimbre.builder()
            .category(dto.getCategory())
            .title(dto.getTitle())
            .description(dto.getDescription())
            .language(dto.getLanguage())
            .date(dto.getDate())
            .startTime(LocalTime.parse(dto.getStartTime()))
            .endTime(LocalTime.parse(dto.getEndTime()))
            .maxAttendees(dto.getMaxAttendees() != null ? dto.getMaxAttendees().longValue() : null)
            .creator(creator)
            .build();
}

private void updateEntityFromDTO(ActivitiesUrdimbre activity, ActivitiesUrdimbreRequestDTO dto) {
    activity.setCategory(dto.getCategory());
    activity.setTitle(dto.getTitle());
    activity.setDescription(dto.getDescription());
    activity.setLanguage(dto.getLanguage());
    activity.setDate(dto.getDate());
    activity.setStartTime(LocalTime.parse(dto.getStartTime()));
    activity.setEndTime(LocalTime.parse(dto.getEndTime()));
    activity.setMaxAttendees(dto.getMaxAttendees() != null ? dto.getMaxAttendees().longValue() : null);
}

private ActivitiesUrdimbreResponseDTO convertToDto(ActivitiesUrdimbre activity) {
    Long currentAttendees = attendanceRepository.countByActivityId_IdAndStatus(
            activity.getId(),
            com.urdimbre.urdimbre.model.AttendanceStatus.CONFIRMED);


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
            .currentAttendees(currentAttendees.intValue())
            .createdAt(activity.getCreatedAt())
            .creator(activity.getCreator() != null ? activity.getCreator().getUsername() : null)
            .build();
}

}