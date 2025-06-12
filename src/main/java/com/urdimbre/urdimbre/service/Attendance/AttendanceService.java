package com.urdimbre.urdimbre.service.attendance;

import com.urdimbre.urdimbre.dto.attendance.AttendanceResponseDTO;

public interface AttendanceService {

   AttendanceResponseDTO registerAttendance( Long activitiesId, Long userId);

}
