package com.urdimbre.urdimbre.service.attendance;

import java.util.List;

import com.urdimbre.urdimbre.dto.attendance.AttendanceResponseDTO;

public interface AttendanceService {

   AttendanceResponseDTO registerAttendance(Long activitiesId, Long userId);

   List<AttendanceResponseDTO> getAttendancesByActivity(Long activityId);

   List<AttendanceResponseDTO> getAttendancesByUser(Long userId);

   void cancelAttendance(Long attendanceId, Long userId);

   Long getConfirmedAttendeesCount(Long activityId);

   boolean isUserRegistered(Long userId, Long activityId);
}
