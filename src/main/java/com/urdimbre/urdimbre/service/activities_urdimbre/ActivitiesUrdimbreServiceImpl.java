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
import com.urdimbre.urdimbre.model.ActivitiesUrdimbre;
import com.urdimbre.urdimbre.model.Category;
import com.urdimbre.urdimbre.model.Language;
import com.urdimbre.urdimbre.repository.ActivitiesUrdimbreRepository;
import com.urdimbre.urdimbre.repository.AttendanceRepository;

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

        @Override
        public ActivitiesUrdimbreResponseDTO createActivitiesUrdimbre(ActivitiesUrdimbreRequestDTO dto) {
                log.info("🎨 Creando nueva actividad: {}", dto.getTitle());

                ActivitiesUrdimbre activity = new ActivitiesUrdimbre();
                activity.setCategory(dto.getCategory());
                activity.setTitle(dto.getTitle());
                activity.setDescription(dto.getDescription());
                activity.setLanguage(dto.getLanguage());
                activity.setDate(LocalDate.parse(dto.getDate()));
                activity.setStartTime(LocalTime.parse(dto.getStartTime()));
                activity.setEndTime(LocalTime.parse(dto.getEndTime()));
                activity.setMaxAttendees(dto.getMaxAttendees() != null ? dto.getMaxAttendees().longValue() : null);

                ActivitiesUrdimbre saved = activitiesUrdimbreRepository.save(activity);
                log.info("✅ Actividad creada exitosamente - ID: {}", saved.getId());

                return ActivitiesUrdimbreResponseDTO.builder()
                                .id(saved.getId())
                                .category(saved.getCategory())
                                .title(saved.getTitle())
                                .description(saved.getDescription())
                                .language(saved.getLanguage())
                                .date(saved.getDate())
                                .startTime(saved.getStartTime())
                                .endTime(saved.getEndTime())
                                .maxAttendees(saved.getMaxAttendees() != null ? saved.getMaxAttendees().intValue()
                                                : null)
                                .currentAttendees(0)
                                .build();
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
                return activitiesUrdimbreRepository.findAllByDate(date)
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

        // ✅ Método sin parámetros requerido por la interfaz
        @Override
        public List<ActivitiesUrdimbreResponseDTO> getUpcomingActivities() {
                log.info("🔮 Obteniendo actividades futuras (sin parámetros)");
                LocalDate today = LocalDate.now();
                return activitiesUrdimbreRepository.findAllByDateGreaterThanEqual(today)
                                .stream()
                                .map(this::convertToDto)
                                .toList();
        }

        // ✅ Método con parámetros de paginación (sobrecarga)
        @Override
        public List<ActivitiesUrdimbreResponseDTO> getUpcomingActivities(int days, int page, int size) {
                log.info("🔮 Obteniendo actividades futuras para {} días (página: {}, tamaño: {})", days, page, size);

                LocalDate today = LocalDate.now();
                LocalDate futureDate = today.plusDays(days);

                Pageable pageable = PageRequest.of(page, size,
                                Sort.by("date").ascending().and(Sort.by("startTime").ascending()));

                // ✅ Usar método Spring Data JPA estándar que sí existe
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

                activity.setCategory(dto.getCategory());
                activity.setTitle(dto.getTitle());
                activity.setDescription(dto.getDescription());
                activity.setLanguage(dto.getLanguage());
                activity.setDate(LocalDate.parse(dto.getDate()));
                activity.setStartTime(LocalTime.parse(dto.getStartTime()));
                activity.setEndTime(LocalTime.parse(dto.getEndTime()));
                activity.setMaxAttendees(dto.getMaxAttendees() != null ? dto.getMaxAttendees().longValue() : null);

                ActivitiesUrdimbre saved = activitiesUrdimbreRepository.save(activity);
                log.info("✅ Actividad actualizada exitosamente");

                return convertToDto(saved);
        }

        private ActivitiesUrdimbreResponseDTO convertToDto(ActivitiesUrdimbre activity) {
                // Obtener número actual de asistentes confirmados
                Long currentAttendees = attendanceRepository.countByActivityId_IdAndStatus(
                                activity.getId(),
                                com.urdimbre.urdimbre.model.AttendanceStatus.CONFIRMED);

                return new ActivitiesUrdimbreResponseDTO(
                                activity.getId(),
                                activity.getCategory(),
                                activity.getTitle(),
                                activity.getDescription(),
                                activity.getLanguage(),
                                activity.getDate(),
                                activity.getStartTime(),
                                activity.getEndTime(),
                                activity.getMaxAttendees() != null ? activity.getMaxAttendees().intValue() : null,
                                currentAttendees.intValue());
        }
}