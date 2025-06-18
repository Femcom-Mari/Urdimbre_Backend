package com.urdimbre.urdimbre.dto.attendance;

import com.urdimbre.urdimbre.model.AttendanceStatus;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AttendanceRequestDTO {

    private AttendanceStatus status;

    @NotNull(message = "El ID de la actividad es obligatorio")
    private Long activityId;

    @NotNull(message = "El ID del usuario es obligatorio")
    private Long userId;
}
