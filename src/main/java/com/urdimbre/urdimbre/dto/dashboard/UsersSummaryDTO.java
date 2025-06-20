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
public class UsersSummaryDTO {
    private long totalAdmins;
    private long totalOrganizers;
    private long totalUsers;
    private long totalAllUsers;

    // ✅ Métodos de utilidad para porcentajes
    public double getAdminPercentage() {
        return totalAllUsers > 0 ? (double) totalAdmins / totalAllUsers * 100 : 0.0;
    }

    public double getOrganizerPercentage() {
        return totalAllUsers > 0 ? (double) totalOrganizers / totalAllUsers * 100 : 0.0;
    }

    public double getUserPercentage() {
        return totalAllUsers > 0 ? (double) totalUsers / totalAllUsers * 100 : 0.0;
    }

    public boolean hasUsers() {
        return totalAllUsers > 0;
    }
}