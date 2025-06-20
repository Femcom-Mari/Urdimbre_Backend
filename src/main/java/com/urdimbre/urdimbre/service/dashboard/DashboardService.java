package com.urdimbre.urdimbre.service.dashboard;

import java.util.List;

import com.urdimbre.urdimbre.dto.dashboard.ActivitiesOverviewDTO;
import com.urdimbre.urdimbre.dto.dashboard.DashboardDTO;
import com.urdimbre.urdimbre.dto.dashboard.RecentActivityDTO;
import com.urdimbre.urdimbre.dto.dashboard.SystemStatsDTO;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

public interface DashboardService {

    DashboardDTO getDashboardData(UserContext userContext);

    ActivitiesOverviewDTO getActivitiesSummary(UserContext userContext);

    RecentActivityDTO getRecentActivities(UserContext userContext);

    SystemStatsDTO getSystemStats();

    ActivitiesOverviewDTO getOrganizerStats(String username);

    @Getter
    @RequiredArgsConstructor
    class UserContext {
        private final String username;
        private final List<String> roles;
    }
}
