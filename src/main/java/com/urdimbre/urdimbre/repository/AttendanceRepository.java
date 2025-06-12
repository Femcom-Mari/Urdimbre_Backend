package com.urdimbre.urdimbre.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.urdimbre.urdimbre.model.Attendance;

@Repository
public interface AttendanceRepository extends JpaRepository<Attendance, Long> {
Boolean existsByUser_IdAndActivityId_Id(Long userId, Long activityId);

}
