package com.urdimbre.urdimbre.service.attendance;

import java.util.List;

import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.dto.attendance.AttendanceResponseDTO;
import com.urdimbre.urdimbre.exception.ActivityNotFoundException;
import com.urdimbre.urdimbre.exception.AttendanceAlreadyExistsException;
import com.urdimbre.urdimbre.exception.UserNotFoundException;
import com.urdimbre.urdimbre.model.ActivitiesUrdimbre;
import com.urdimbre.urdimbre.model.Attendance;
import com.urdimbre.urdimbre.model.AttendanceStatus;
import com.urdimbre.urdimbre.model.User;
import com.urdimbre.urdimbre.repository.ActivitiesUrdimbreRepository;
import com.urdimbre.urdimbre.repository.AttendanceRepository;
import com.urdimbre.urdimbre.repository.UserRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AttendanceServiceImpl implements AttendanceService {

        private final AttendanceRepository attendanceRepository;
        private final UserRepository userRepository;
        private final ActivitiesUrdimbreRepository activitiesUrdimbreRepository;

        @Override
        @Transactional
        public AttendanceResponseDTO registerAttendance(Long activityId, Long userId) {
                log.info("🎯 Registrando asistencia - Usuario: {}, Actividad: {}", userId, activityId);

                User user = userRepository.findById(userId)
                                .orElseThrow(() -> new UserNotFoundException(
                                                "Usuario no encontrado con id: " + userId));

                ActivitiesUrdimbre activity = activitiesUrdimbreRepository.findById(activityId)
                                .orElseThrow(() -> new ActivityNotFoundException(
                                                "Actividad no encontrada con id: " + activityId));

                boolean alreadyExists = attendanceRepository.existsByUser_IdAndActivityId_Id(userId, activityId);
                if (alreadyExists) {
                        throw new AttendanceAlreadyExistsException(
                                        "La asistencia ya fue registrada para esta actividad.");
                }

                // ✅ Verificar capacidad máxima usando método JPA derivado
                Long currentAttendees = attendanceRepository.countByActivityId_IdAndStatus(activityId,
                                AttendanceStatus.CONFIRMED);
                if (currentAttendees >= activity.getMaxAttendees()) {
                        log.warn("⚠️ Actividad {} ha alcanzado su capacidad máxima: {}/{}",
                                        activityId, currentAttendees, activity.getMaxAttendees());
                        throw new RuntimeException("La actividad ha alcanzado su capacidad máxima");
                }

                Attendance attendance = new Attendance();
                attendance.setUser(user);
                attendance.setActivityId(activity);
                attendance.setStatus(AttendanceStatus.CONFIRMED);

                Attendance saved = attendanceRepository.save(attendance);
                log.info("✅ Asistencia registrada exitosamente - ID: {}", saved.getId());

                return new AttendanceResponseDTO(
                                saved.getId(),
                                user.getId(),
                                user.getUsername(),
                                activity.getId(),
                                activity.getTitle(),
                                saved.getStatus());
        }

        @Override
        public List<AttendanceResponseDTO> getAttendancesByActivity(Long activityId) {
                log.info("📋 Obteniendo asistencias para actividad: {}", activityId);

                activitiesUrdimbreRepository.findById(activityId)
                                .orElseThrow(() -> new ActivityNotFoundException(
                                                "Actividad no encontrada con id: " + activityId));

                List<Attendance> attendances = attendanceRepository.findByActivityId_Id(activityId);

                return attendances.stream()
                                .map(attendance -> new AttendanceResponseDTO(
                                                attendance.getId(),
                                                attendance.getUser().getId(),
                                                attendance.getUser().getUsername(),
                                                attendance.getActivityId().getId(),
                                                attendance.getActivityId().getTitle(),
                                                attendance.getStatus()))
                                .toList();
        }

        @Override
        public List<AttendanceResponseDTO> getAttendancesByUser(Long userId) {
                log.info("👤 Obteniendo asistencias para usuario: {}", userId);

                userRepository.findById(userId)
                                .orElseThrow(() -> new UserNotFoundException(
                                                "Usuario no encontrado con id: " + userId));

                List<Attendance> attendances = attendanceRepository.findByUser_Id(userId);

                return attendances.stream()
                                .map(attendance -> new AttendanceResponseDTO(
                                                attendance.getId(),
                                                attendance.getUser().getId(),
                                                attendance.getUser().getUsername(),
                                                attendance.getActivityId().getId(),
                                                attendance.getActivityId().getTitle(),
                                                attendance.getStatus()))
                                .toList();
        }

        @Override
        @Transactional
        public void cancelAttendance(Long attendanceId, Long userId) {
                log.info("❌ Cancelando asistencia: {} para usuario: {}", attendanceId, userId);

                Attendance attendance = attendanceRepository.findById(attendanceId)
                                .orElseThrow(() -> new RuntimeException(
                                                "Asistencia no encontrada con id: " + attendanceId));

                if (!attendance.getUser().getId().equals(userId)) {
                        throw new RuntimeException("No tienes permisos para cancelar esta asistencia");
                }

                attendance.setStatus(AttendanceStatus.CANCELLED);
                attendanceRepository.save(attendance);

                log.info("✅ Asistencia cancelada exitosamente");
        }

        @Override
        public Long getConfirmedAttendeesCount(Long activityId) {
                return attendanceRepository.countByActivityId_IdAndStatus(activityId, AttendanceStatus.CONFIRMED);
        }

        @Override
        public boolean isUserRegistered(Long userId, Long activityId) {
                return attendanceRepository.existsByUser_IdAndActivityId_Id(userId, activityId);
        }
}
