package com.urdimbre.urdimbre.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.urdimbre.urdimbre.model.InviteCode;
import com.urdimbre.urdimbre.model.InviteCode.InviteStatus;

@Repository
public interface InviteCodeRepository extends JpaRepository<InviteCode, Long> {

        Optional<InviteCode> findByCode(String code);

        boolean existsByCode(String code);

        List<InviteCode> findByStatus(InviteStatus status);

        Page<InviteCode> findByStatus(InviteStatus status, Pageable pageable);

        List<InviteCode> findByCreatedBy(String createdBy);

        Page<InviteCode> findByCreatedByOrderByCreatedAtDesc(String createdBy, Pageable pageable);

        long countByStatus(InviteStatus status);

        long countByCreatedBy(String createdBy);

        long countByCreatedByAndStatus(String createdBy, InviteStatus status);

        List<InviteCode> findByStatusAndExpiresAtBefore(InviteStatus status, LocalDateTime now);

        List<InviteCode> findByStatusAndExpiresAtBetween(InviteStatus status, LocalDateTime now,
                        LocalDateTime soonThreshold);

        Optional<InviteCode> findByCodeAndStatus(String code, InviteStatus status);

        List<InviteCode> findByCreatedAtBefore(LocalDateTime cutoffDate);

        List<InviteCode> findByStatusAndCreatedAtBefore(InviteStatus status, LocalDateTime cutoffDate);

        List<InviteCode> findByCurrentUsesGreaterThanOrderByCurrentUsesDesc(int minUses);

        Page<InviteCode> findByCurrentUsesGreaterThanOrderByCurrentUsesDesc(int minUses, Pageable pageable);

        List<InviteCode> findAllByOrderByCreatedAtDesc();

        Page<InviteCode> findAllByOrderByCreatedAtDesc(Pageable pageable);

        Page<InviteCode> findByCodeContainingIgnoreCaseOrDescriptionContainingIgnoreCase(
                        String code, String description, Pageable pageable);
}