package com.urdimbre.urdimbre.dto.dashboard;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ActivitiesOverviewDTO {
    private long totalActivities;
    private long upcomingActivities;
    private long pastActivities;
    private long thisWeekActivities;

    // ✅ Métodos de utilidad
    public double getUpcomingPercentage() {
        return totalActivities > 0 ? (double) upcomingActivities / totalActivities * 100 : 0.0;
    }

    public double getPastPercentage() {
        return totalActivities > 0 ? (double) pastActivities / totalActivities * 100 : 0.0;
    }

    public boolean hasActivities() {
        return totalActivities > 0;
    }
}