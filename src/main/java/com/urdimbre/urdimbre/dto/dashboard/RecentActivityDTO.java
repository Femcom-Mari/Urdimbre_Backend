package com.urdimbre.urdimbre.dto.dashboard;

import java.util.List;

import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreResponseDTO;

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
public class RecentActivityDTO {
    private List<ActivitiesUrdimbreResponseDTO> recentActivities;
}
