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

        // ================================
        // MÉTODOS AUTOMÁTICOS DE SPRING DATA JPA
        // (No necesitan @Query - Spring los genera automáticamente)
        // ================================

        /**
         * 🔍 Buscar código de invitación por código
         */
        Optional<InviteCode> findByCode(String code);

        /**
         * 🔢 Verificar si existe código
         */
        boolean existsByCode(String code);

        /**
         * 📋 Buscar códigos por estado
         */
        List<InviteCode> findByStatus(InviteStatus status);

        /**
         * 📋 Buscar códigos por estado con paginación
         */
        Page<InviteCode> findByStatus(InviteStatus status, Pageable pageable);

        /**
         * 👤 Buscar códigos creados por un usuario
         */
        List<InviteCode> findByCreatedBy(String createdBy);

        /**
         * 👤 Buscar códigos creados por un usuario con paginación y orden
         */
        Page<InviteCode> findByCreatedByOrderByCreatedAtDesc(String createdBy, Pageable pageable);

        /**
         * 📊 Contar códigos por estado
         */
        long countByStatus(InviteStatus status);

        /**
         * 📊 Contar códigos por usuario
         */
        long countByCreatedBy(String createdBy);

        /**
         * 📊 Contar códigos activos por usuario
         */
        long countByCreatedByAndStatus(String createdBy, InviteStatus status);

        /**
         * ⏰ Buscar códigos expirados (status ACTIVE pero fecha pasada)
         */
        List<InviteCode> findByStatusAndExpiresAtBefore(InviteStatus status, LocalDateTime now);

        /**
         * ⏰ Buscar códigos que expiran pronto
         */
        List<InviteCode> findByStatusAndExpiresAtBetween(InviteStatus status, LocalDateTime now,
                        LocalDateTime soonThreshold);

        /**
         * 🔍 Buscar códigos válidos por código (lógica en Service)
         * Para validar código, se recomienda implementar la lógica en el Service
         */
        Optional<InviteCode> findByCodeAndStatus(String code, InviteStatus status);

        /**
         * 📅 Buscar códigos creados antes de una fecha
         */
        List<InviteCode> findByCreatedAtBefore(LocalDateTime cutoffDate);

        /**
         * 📅 Buscar códigos por estado y creados antes de una fecha
         */
        List<InviteCode> findByStatusAndCreatedAtBefore(InviteStatus status, LocalDateTime cutoffDate);

        /**
         * 📈 Buscar códigos ordenados por uso (mayor a menor)
         */
        List<InviteCode> findByCurrentUsesGreaterThanOrderByCurrentUsesDesc(int minUses);

        /**
         * 📈 Buscar códigos más usados con paginación
         */
        Page<InviteCode> findByCurrentUsesGreaterThanOrderByCurrentUsesDesc(int minUses, Pageable pageable);

        /**
         * 🔍 Buscar todos los códigos ordenados por fecha de creación
         */
        List<InviteCode> findAllByOrderByCreatedAtDesc();

        /**
         * 🔍 Buscar todos los códigos con paginación ordenados por fecha
         */
        Page<InviteCode> findAllByOrderByCreatedAtDesc(Pageable pageable);
}