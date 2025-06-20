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
public class SystemStatsDTO {
    private long totalUsers;
    private long totalActivities;
    private long totalAttendances;
    private long confirmedAttendances;
    private long pendingAttendances;
    private long activitiesThisMonth;

    // ✅ Métodos de utilidad para estadísticas
    public double getAttendanceRate() {
        return totalAttendances > 0 ? (double) confirmedAttendances / totalAttendances * 100 : 0.0;
    }

    public double getAverageAttendeesPerActivity() {
        return totalActivities > 0 ? (double) totalAttendances / totalActivities : 0.0;
    }

    public long getCancelledAttendances() {
        return totalAttendances - confirmedAttendances - pendingAttendances;
    }
}