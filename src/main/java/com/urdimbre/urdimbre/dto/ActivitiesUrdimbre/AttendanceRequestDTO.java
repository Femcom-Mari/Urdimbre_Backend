package com.urdimbre.urdimbre.dto.ActivitiesUrdimbre;

import com.urdimbre.urdimbre.model.AttendanceStatus;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AttendanceRequestDTO {

    private Integer activitiesUrdimbreId;
    private AttendanceStatus status;
}
