package com.urdimbre.urdimbre.dto.dashboard;

import java.time.LocalDateTime;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DashboardDTO {
    private String username;
    private List<String> roles;
    private SystemStatsDTO systemStats; // Solo para ADMIN
    private UsersSummaryDTO usersSummary; // Solo para ADMIN
    private ActivitiesOverviewDTO activitiesOverview;
    private RecentActivityDTO recentActivity;
    private LocalDateTime generatedAt;
}
