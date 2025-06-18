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

    public AttendanceResponseDTO (Long id, Long userId, String username, Long activityId, String activityTitle ) {
        this.id = id;
        this.userId = userId;
        this.username = username;
        this.activityId = activityId;
        this.activityTitle =activityTitle;
        this.status = AttendanceStatus.CONFIRMED;
    }
}
