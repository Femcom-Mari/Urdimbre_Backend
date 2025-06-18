package com.urdimbre.urdimbre.dto.attendance;

import com.urdimbre.urdimbre.model.AttendanceStatus;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AttendanceResponseDTO {

    private Long id;
    private Long userId;
    private String username;
    private Long activityId;
    private String activityTitle;
    private AttendanceStatus status;

}