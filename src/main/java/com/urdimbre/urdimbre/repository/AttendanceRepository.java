package com.urdimbre.urdimbre.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.urdimbre.urdimbre.model.Attendance;
import com.urdimbre.urdimbre.model.AttendanceStatus;

@Repository
public interface AttendanceRepository extends JpaRepository<Attendance, Long> {

    Boolean existsByUser_IdAndActivityId_Id(Long userId, Long activityId);

    Long countByActivityId_IdAndStatus(Long activityId, AttendanceStatus status);

    List<Attendance> findByActivityId_Id(Long activityId);

    List<Attendance> findByUser_Id(Long userId);

    List<Attendance> findByUser_IdAndStatus(Long userId, AttendanceStatus status);

    List<Attendance> findByActivityId_IdAndStatus(Long activityId, AttendanceStatus status);

    List<Attendance> findByUser_IdAndActivityId_Id(Long userId, Long activityId);

    void deleteByActivityId_Id(Long activityId);

    void deleteByUser_Id(Long userId);
}
