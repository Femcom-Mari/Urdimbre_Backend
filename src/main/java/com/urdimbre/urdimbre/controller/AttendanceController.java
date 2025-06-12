package com.urdimbre.urdimbre.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.urdimbre.urdimbre.dto.attendance.AttendanceResponseDTO;
import com.urdimbre.urdimbre.service.attendance.AttendanceService;
import lombok.AllArgsConstructor;


@RestController
@AllArgsConstructor
@RequestMapping("/api/attendance")
public class AttendanceController {

    private final AttendanceService attendanceService;


@PostMapping("/user/{userId}/activities/{activitiesId}")
public ResponseEntity<AttendanceResponseDTO> registerAttendance(
    @PathVariable Long userId,
    @PathVariable Long activitiesId) {

    AttendanceResponseDTO response = attendanceService.registerAttendance(activitiesId, userId);
    return ResponseEntity.status(HttpStatus.CREATED).body(response);
}

}
