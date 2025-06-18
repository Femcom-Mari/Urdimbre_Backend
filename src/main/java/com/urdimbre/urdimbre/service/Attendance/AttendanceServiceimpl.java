package com.urdimbre.urdimbre.service.attendance;

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

@Service
@RequiredArgsConstructor
public class AttendanceServiceimpl implements AttendanceService {

    private final AttendanceRepository attendanceRepository;
    private final UserRepository userRepository;
    private final ActivitiesUrdimbreRepository activitiesUrdimbreRepository;

    @Override
    @Transactional
    public AttendanceResponseDTO registerAttendance(Long activityId, Long userId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("Usuario no encontrado con id: " + userId));

        ActivitiesUrdimbre activity = activitiesUrdimbreRepository.findById(activityId)
                .orElseThrow(() -> new ActivityNotFoundException("Actividad no encontrada con id: " + activityId));

        boolean alreadyExists = attendanceRepository.existsByUser_IdAndActivityId_Id(userId, activityId);
        if (alreadyExists) {
            throw new AttendanceAlreadyExistsException("La asistencia ya fue registrada para esta actividad.");
        }

        Attendance attendance = new Attendance();
        attendance.setUser(user);
        attendance.setActivityId(activity);
        attendance.setStatus(AttendanceStatus.CONFIRMED);

        Attendance saved = attendanceRepository.save(attendance);

        return new AttendanceResponseDTO(
                saved.getId(),
                user.getId(),
                user.getUsername(),
                activity.getId(),
                activity.getTitle(),
                saved.getStatus());
    }
}
