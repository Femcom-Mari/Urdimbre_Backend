
package com.urdimbre.urdimbre.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.dto.attendance.AttendanceResponseDTO;
import com.urdimbre.urdimbre.service.attendance.AttendanceService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/attendance")
@Slf4j
public class AttendanceController {

    private final AttendanceService attendanceService;

    // ================================
    // ENDPOINTS PARA USUARIOS - Registrar asistencia
    // ================================

    @PostMapping("/user/{userId}/activities/{activitiesId}")
    public ResponseEntity<AttendanceResponseDTO> registerAttendance(
            @PathVariable Long userId,
            @PathVariable Long activitiesId) {
        log.info("🎯 Registrar asistencia - Usuario: {}, Actividad: {}", userId, activitiesId);
        AttendanceResponseDTO response = attendanceService.registerAttendance(activitiesId, userId);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @DeleteMapping("/{attendanceId}/user/{userId}")
    public ResponseEntity<Void> cancelAttendance(
            @PathVariable Long attendanceId,
            @PathVariable Long userId) {
        log.info("❌ Cancelar asistencia - ID: {}, Usuario: {}", attendanceId, userId);
        attendanceService.cancelAttendance(attendanceId, userId);
        return ResponseEntity.noContent().build();
    }

    // ================================
    // ENDPOINTS DE CONSULTA - Todos los usuarios autenticados
    // ================================

    @GetMapping("/user/{userId}")
    public ResponseEntity<List<AttendanceResponseDTO>> getUserAttendances(@PathVariable Long userId) {
        log.info("👤 Obtener asistencias del usuario: {}", userId);
        List<AttendanceResponseDTO> attendances = attendanceService.getAttendancesByUser(userId);
        return ResponseEntity.ok(attendances);
    }

    // ================================
    // ENDPOINTS PARA ORGANIZADORES Y ADMINS
    // ================================

    @GetMapping("/activity/{activityId}")
    @PreAuthorize("hasRole('ORGANIZER') or hasRole('ADMIN')")
    public ResponseEntity<List<AttendanceResponseDTO>> getActivityAttendances(@PathVariable Long activityId) {
        log.info("📊 Obtener asistencias de actividad: {}", activityId);
        List<AttendanceResponseDTO> attendances = attendanceService.getAttendancesByActivity(activityId);
        return ResponseEntity.ok(attendances);
    }

    @GetMapping("/activity/{activityId}/count")
    @PreAuthorize("hasRole('ORGANIZER') or hasRole('ADMIN')")
    public ResponseEntity<Long> getConfirmedAttendeesCount(@PathVariable Long activityId) {
        log.info("🔢 Contar asistentes confirmados de actividad: {}", activityId);
        Long count = attendanceService.getConfirmedAttendeesCount(activityId);
        return ResponseEntity.ok(count);
    }

    @GetMapping("/user/{userId}/activity/{activityId}/check")
    public ResponseEntity<Boolean> checkUserRegistration(
            @PathVariable Long userId,
            @PathVariable Long activityId) {
        log.info("✅ Verificar registro - Usuario: {}, Actividad: {}", userId, activityId);
        boolean isRegistered = attendanceService.isUserRegistered(userId, activityId);
        return ResponseEntity.ok(isRegistered);
    }
}