package com.urdimbre.urdimbre.service.organizer;

import java.time.LocalDate;
import java.util.List;

import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreResponseDTO;
import com.urdimbre.urdimbre.repository.ActivitiesUrdimbreRepository;
import com.urdimbre.urdimbre.repository.AttendanceRepository;
import com.urdimbre.urdimbre.service.activities_urdimbre.ActivitiesUrdimbreService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class OrganizerDashboardService {

    private final ActivitiesUrdimbreRepository activitiesRepository;
    private final AttendanceRepository attendanceRepository;
    private final ActivitiesUrdimbreService activitiesService;

    /**
     * Obtiene dashboard completo para organizador
     */
    public OrganizerDashboardDTO getDashboard(String organizerUsername) {
        log.info("📊 Generando dashboard para organizador: {}", organizerUsername);

        // Filtrar por organizador cuando tengamos ese campo en ActivitiesUrdimbre
        // Por ahora mostramos todas las actividades

        return OrganizerDashboardDTO.builder()
                .organizerName(organizerUsername)
                .totalActivities(getTotalActivities())
                .upcomingActivities(getUpcomingActivitiesCount())
                .totalAttendees(getTotalAttendees())
                .activitiesThisMonth(getActivitiesThisMonth())
                .recentActivities(getRecentActivities())
                .upcomingActivitiesList(getUpcomingActivitiesList())
                .monthlyStats(getMonthlyStats())
                .build();
    }

    /**
     * Obtiene actividades del organizador (cuando implementemos el campo organizer)
     */
    public List<ActivitiesUrdimbreResponseDTO> getOrganizerActivities(String organizerUsername, int page, int size) {
        log.info("📋 Obteniendo actividades del organizador: {}", organizerUsername);

        // TODO: Implementar cuando agregues campo organizer_id a ActivitiesUrdimbre
        // Por ahora devuelve todas las actividades
        return activitiesService.getAllActivities(page, size);
    }

    // ================================
    // MÉTODOS PRIVADOS PARA ESTADÍSTICAS
    // ================================

    private long getTotalActivities() {
        return activitiesRepository.count();
    }

    private long getUpcomingActivitiesCount() {
        return activitiesRepository.countByDateGreaterThanEqual(LocalDate.now());
    }

    private long getTotalAttendees() {
        return attendanceRepository.count();
    }

    private long getActivitiesThisMonth() {
        LocalDate startOfMonth = LocalDate.now().withDayOfMonth(1);
        LocalDate endOfMonth = startOfMonth.plusMonths(1).minusDays(1);
        return activitiesRepository.countByDateBetween(startOfMonth, endOfMonth);
    }

    private List<ActivitiesUrdimbreResponseDTO> getRecentActivities() {
        List<com.urdimbre.urdimbre.model.ActivitiesUrdimbre> recentActivities = activitiesRepository
                .findAllByOrderByDateDesc()
                .stream()
                .limit(5)
                .toList();

        return recentActivities.stream()
                .map(this::convertToDto)
                .toList();
    }

    private List<ActivitiesUrdimbreResponseDTO> getUpcomingActivitiesList() {
        return activitiesRepository.findByDateGreaterThanEqual(LocalDate.now())
                .stream()
                .limit(10)
                .map(this::convertToDto)
                .toList();
    }

    private List<MonthlyStatsDTO> getMonthlyStats() {
        // Implementar estadísticas mensuales
        return List.of(
                MonthlyStatsDTO.builder()
                        .month("Enero")
                        .activitiesCount(getActivitiesThisMonth())
                        .attendeesCount(getTotalAttendees())
                        .build());
    }

    private ActivitiesUrdimbreResponseDTO convertToDto(com.urdimbre.urdimbre.model.ActivitiesUrdimbre activity) {
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
                .build();
    }

    // ================================
    // DTOs INTERNOS//llevar a la carpeta dto
    // ================================

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class OrganizerDashboardDTO {
        private String organizerName;
        private long totalActivities;
        private long upcomingActivities;
        private long totalAttendees;
        private long activitiesThisMonth;
        private List<ActivitiesUrdimbreResponseDTO> recentActivities;
        private List<ActivitiesUrdimbreResponseDTO> upcomingActivitiesList;
        private List<MonthlyStatsDTO> monthlyStats;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class MonthlyStatsDTO {
        private String month;
        private long activitiesCount;
        private long attendeesCount;
    }
}