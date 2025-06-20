package com.urdimbre.urdimbre.service.dashboard;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreResponseDTO;
import com.urdimbre.urdimbre.dto.dashboard.ActivitiesOverviewDTO;
import com.urdimbre.urdimbre.dto.dashboard.DashboardDTO;
import com.urdimbre.urdimbre.dto.dashboard.RecentActivityDTO;
import com.urdimbre.urdimbre.dto.dashboard.SystemStatsDTO;
import com.urdimbre.urdimbre.dto.dashboard.UsersSummaryDTO;
import com.urdimbre.urdimbre.model.ActivitiesUrdimbre;
import com.urdimbre.urdimbre.model.AttendanceStatus;
import com.urdimbre.urdimbre.repository.ActivitiesUrdimbreRepository;
import com.urdimbre.urdimbre.repository.AttendanceRepository;
import com.urdimbre.urdimbre.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class DashboardServiceImpl implements DashboardService {

        private final ActivitiesUrdimbreRepository activitiesRepository;
        private final AttendanceRepository attendanceRepository;
        private final UserRepository userRepository;

        @Override
        public DashboardDTO getDashboardData(UserContext userContext) {
                log.info("🎯 Generando dashboard para usuario: {} con roles: {}",
                                userContext.getUsername(), userContext.getRoles());

                boolean isAdmin = userContext.getRoles().contains("ROLE_ADMIN");

                DashboardDTO.DashboardDTOBuilder builder = DashboardDTO.builder()
                                .username(userContext.getUsername())
                                .roles(userContext.getRoles())
                                .activitiesOverview(getActivitiesSummary(userContext))
                                .recentActivity(getRecentActivities(userContext))
                                .generatedAt(LocalDateTime.now());

                if (isAdmin) {
                        builder.systemStats(getSystemStats())
                                        .usersSummary(getUsersSummary());
                }

                DashboardDTO dashboard = builder.build();

                log.info("✅ Dashboard generado exitosamente para usuario: {} - Actividades: {}",
                                userContext.getUsername(), dashboard.getActivitiesOverview().getTotalActivities());

                return dashboard;
        }

        @Override
        public ActivitiesOverviewDTO getActivitiesSummary(UserContext userContext) {
                log.debug("📊 Obteniendo resumen de actividades para usuario: {}", userContext.getUsername());

                boolean isAdmin = userContext.getRoles().contains("ROLE_ADMIN");

                List<ActivitiesUrdimbre> activities = isAdmin
                                ? activitiesRepository.findAll()
                                : activitiesRepository.findByCreatedBy_Username(userContext.getUsername());

                long upcomingActivities = activities.stream()
                                .filter(activity -> !activity.getDate().isBefore(LocalDate.now()))
                                .count();

                LocalDate weekStart = LocalDate.now();
                LocalDate weekEnd = weekStart.plusDays(7);

                long thisWeekActivities = activities.stream()
                                .filter(activity -> !activity.getDate().isBefore(weekStart) &&
                                                !activity.getDate().isAfter(weekEnd))
                                .count();

                return ActivitiesOverviewDTO.builder()
                                .totalActivities(activities.size())
                                .upcomingActivities(upcomingActivities)
                                .thisWeekActivities(thisWeekActivities)
                                .pastActivities(activities.size() - (int) upcomingActivities)
                                .build();
        }

        @Override
        public RecentActivityDTO getRecentActivities(UserContext userContext) {
                log.debug("⏰ Obteniendo actividades recientes para usuario: {}", userContext.getUsername());

                boolean isAdmin = userContext.getRoles().contains("ROLE_ADMIN");

                List<ActivitiesUrdimbre> activities = isAdmin
                                ? activitiesRepository.findAll()
                                : activitiesRepository.findByCreatedBy_Username(userContext.getUsername());

                List<ActivitiesUrdimbreResponseDTO> recentActivities = activities.stream()
                                .sorted((a, b) -> {
                                        if (a.getDate().equals(b.getDate())) {
                                                return a.getStartTime().compareTo(b.getStartTime());
                                        }
                                        return a.getDate().compareTo(b.getDate());
                                })
                                .limit(10)
                                .map(this::mapToResponseDTO)
                                .toList();

                return RecentActivityDTO.builder()
                                .recentActivities(recentActivities)
                                .build();
        }

        @Override
        public SystemStatsDTO getSystemStats() {
                log.debug("📈 Obteniendo estadísticas del sistema");

                long totalUsers = userRepository.count();
                long totalActivities = activitiesRepository.count();
                long totalAttendances = attendanceRepository.count();

                long confirmedAttendances = attendanceRepository.countByStatus(AttendanceStatus.CONFIRMED);
                long pendingAttendances = attendanceRepository.countByStatus(AttendanceStatus.PENDING);

                LocalDate monthStart = LocalDate.now().withDayOfMonth(1);
                LocalDate monthEnd = monthStart.plusMonths(1).minusDays(1);
                long activitiesThisMonth = activitiesRepository.countByDateBetween(monthStart, monthEnd);

                return SystemStatsDTO.builder()
                                .totalUsers(totalUsers)
                                .totalActivities(totalActivities)
                                .totalAttendances(totalAttendances)
                                .confirmedAttendances(confirmedAttendances)
                                .pendingAttendances(pendingAttendances)
                                .activitiesThisMonth(activitiesThisMonth)
                                .build();
        }

        @Override
        public ActivitiesOverviewDTO getOrganizerStats(String username) {
                log.debug("👤 Obteniendo estadísticas para organizador: {}", username);

                List<ActivitiesUrdimbre> organizerActivities = activitiesRepository.findByCreatedBy_Username(username);

                long upcomingActivities = organizerActivities.stream()
                                .filter(activity -> !activity.getDate().isBefore(LocalDate.now()))
                                .count();

                return ActivitiesOverviewDTO.builder()
                                .totalActivities(organizerActivities.size())
                                .upcomingActivities(upcomingActivities)
                                .pastActivities(organizerActivities.size() - (int) upcomingActivities)
                                .build();
        }

        private UsersSummaryDTO getUsersSummary() {
                log.debug("👥 Obteniendo resumen de usuarios");

                long totalAdmins = userRepository.countByRoles_Name("ROLE_ADMIN");
                long totalOrganizers = userRepository.countByRoles_Name("ROLE_ORGANIZER");
                long totalRegularUsers = userRepository.countByRoles_Name("ROLE_USER");

                return UsersSummaryDTO.builder()
                                .totalAdmins(totalAdmins)
                                .totalOrganizers(totalOrganizers)
                                .totalUsers(totalRegularUsers)
                                .totalAllUsers(totalAdmins + totalOrganizers + totalRegularUsers)
                                .build();
        }

        private ActivitiesUrdimbreResponseDTO mapToResponseDTO(ActivitiesUrdimbre activity) {
                int confirmedCount = attendanceRepository
                                .countByActivityId_IdAndStatus(activity.getId(), AttendanceStatus.CONFIRMED)
                                .intValue();

                Integer availableSpots = null;
                if (activity.getMaxAttendees() != null) {
                        availableSpots = activity.getMaxAttendees().intValue() - confirmedCount;
                }

                return ActivitiesUrdimbreResponseDTO.builder()
                                .id(activity.getId())
                                .title(activity.getTitle())
                                .description(activity.getDescription())
                                .date(activity.getDate())
                                .startTime(activity.getStartTime())
                                .endTime(activity.getEndTime())
                                .language(activity.getLanguage())
                                .category(activity.getCategory())
                                .maxAttendees(activity.getMaxAttendees() != null ? activity.getMaxAttendees().intValue()
                                                : null)
                                .currentAttendees(confirmedCount)
                                .availableSpots(availableSpots)
                                .createdBy(activity.getCreatedBy().getUsername())
                                .createdAt(activity.getCreatedAt())
                                .build();
        }
}