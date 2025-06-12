package com.urdimbre.urdimbre.dto.attendance;

import com.urdimbre.urdimbre.model.AttendanceStatus;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AttendanceRequestDTO {


private AttendanceStatus status;

private Long activityId;
private Long userId;



}
