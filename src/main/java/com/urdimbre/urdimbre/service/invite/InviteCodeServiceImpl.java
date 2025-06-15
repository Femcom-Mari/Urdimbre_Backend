package com.urdimbre.urdimbre.service.invite;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.urdimbre.urdimbre.dto.invite.BulkInviteCodeRequestDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodeRequestDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodeResponseDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodeStatsDTO;
import com.urdimbre.urdimbre.exception.BadRequestException;
import com.urdimbre.urdimbre.exception.ResourceNotFoundException;
import com.urdimbre.urdimbre.model.InviteCode;
import com.urdimbre.urdimbre.model.InviteCode.InviteStatus;
import com.urdimbre.urdimbre.repository.InviteCodeRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class InviteCodeServiceImpl implements InviteCodeService {

    private static final Logger logger = LoggerFactory.getLogger(InviteCodeServiceImpl.class);
    private static final String CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final int DEFAULT_CODE_LENGTH = 12;
    private static final int MAX_ACTIVE_CODES_PER_USER = 50;

    private final InviteCodeRepository inviteCodeRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    // ✅ USAR APPLICATIONCONTEXT PARA EVITAR REFERENCIA CIRCULAR
    @Autowired
    private ApplicationContext applicationContext;

    // ✅ MÉTODO CRÍTICO PARA EL AUTHCONTROLLER
    @Override
    @Transactional(readOnly = true)
    public Optional<InviteCode> findByCode(String code) {
        logger.debug("🔍 Buscando código de invitación: {}", code);
        return inviteCodeRepository.findByCode(code);
    }

    @Override
    public InviteCodeResponseDTO generateCode(InviteCodeRequestDTO request) {
        logger.info("🎟️ Generando nuevo código de invitación");

        String currentUser = getCurrentUser();
        validateUserLimits(currentUser);

        String code = request.getCustomCode() != null ? validateAndFormatCustomCode(request.getCustomCode())
                : generateUniqueCode();

        LocalDateTime expiresAt = LocalDateTime.now().plusHours(request.getDurationHours());

        InviteCode inviteCode = InviteCode.builder()
                .code(code)
                .description(request.getDescription())
                .expiresAt(expiresAt)
                .maxUses(request.getMaxUses())
                .createdBy(currentUser)
                .status(InviteStatus.ACTIVE)
                .build();

        InviteCode saved = inviteCodeRepository.save(inviteCode);

        logger.info("✅ Código de invitación generado: {} (expira: {})", code, expiresAt);

        return mapToResponseDTO(saved);
    }

    @Override
    public List<InviteCodeResponseDTO> generateBulkCodes(BulkInviteCodeRequestDTO request) {
        logger.info("🎯 Generando {} códigos de invitación en lote", request.getQuantity());

        String currentUser = getCurrentUser();
        validateBulkLimits(currentUser, request.getQuantity());

        List<InviteCode> codes = IntStream.range(0, request.getQuantity())
                .mapToObj(i -> {
                    String code = generateUniqueCodeWithPrefix(request.getPrefix());
                    LocalDateTime expiresAt = LocalDateTime.now().plusHours(request.getDurationHours());

                    return InviteCode.builder()
                            .code(code)
                            .description(request.getDescription())
                            .expiresAt(expiresAt)
                            .maxUses(request.getMaxUses())
                            .createdBy(currentUser)
                            .status(InviteStatus.ACTIVE)
                            .build();
                })
                .toList();

        List<InviteCode> savedCodes = inviteCodeRepository.saveAll(codes);

        logger.info("✅ {} códigos de invitación generados en lote", savedCodes.size());

        return savedCodes.stream()
                .map(this::mapToResponseDTO)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public boolean validateInviteCode(String code) {
        logger.debug("✅ Validando código de invitación: {}", code);

        Optional<InviteCode> inviteCode = findValidByCode(code);
        boolean isValid = inviteCode.isPresent();

        logger.debug("Código {} es válido: {}", code, isValid);
        return isValid;
    }

    @Override
    public InviteCode useInviteCode(String code, String usedBy) {
        logger.info("🎫 Usando código de invitación: {} por usuario: {}", code, usedBy);

        InviteCode inviteCode = findValidByCode(code)
                .orElseThrow(() -> {
                    logger.warn("❌ Código de invitación inválido o expirado: {}", code);
                    return new BadRequestException("Código de invitación inválido o expirado");
                });

        inviteCode.incrementUses(usedBy);
        InviteCode updated = inviteCodeRepository.save(inviteCode);

        logger.info("✅ Código usado exitosamente: {} (usos: {}/{})",
                code, updated.getCurrentUses(), updated.getMaxUses());

        return updated;
    }

    @Override
    @Transactional(readOnly = true)
    public Page<InviteCodeResponseDTO> getUserCodes(Pageable pageable) {
        String currentUser = getCurrentUser();
        logger.debug("📋 Obteniendo códigos del usuario: {} con paginación", currentUser);

        return inviteCodeRepository.findByCreatedByOrderByCreatedAtDesc(currentUser, pageable)
                .map(this::mapToResponseDTO);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<InviteCodeResponseDTO> getAllCodes(Pageable pageable) {
        logger.debug("📋 Obteniendo todos los códigos de invitación con paginación");

        return inviteCodeRepository.findAllByOrderByCreatedAtDesc(pageable)
                .map(this::mapToResponseDTO);
    }

    @Override
    @Transactional(readOnly = true)
    public InviteCodeStatsDTO getStatistics() {
        logger.debug("📊 Calculando estadísticas de códigos de invitación");

        long totalCodes = inviteCodeRepository.count();
        long activeCodes = inviteCodeRepository.countByStatus(InviteStatus.ACTIVE);
        long expiredCodes = inviteCodeRepository.countByStatus(InviteStatus.EXPIRED);
        long exhaustedCodes = inviteCodeRepository.countByStatus(InviteStatus.EXHAUSTED);
        long revokedCodes = inviteCodeRepository.countByStatus(InviteStatus.REVOKED);

        long totalUses = inviteCodeRepository.findAll().stream()
                .mapToLong(InviteCode::getCurrentUses)
                .sum();

        double averageUses = totalCodes > 0 ? (double) totalUses / totalCodes : 0;

        return InviteCodeStatsDTO.builder()
                .totalCodes(totalCodes)
                .activeCodes(activeCodes)
                .expiredCodes(expiredCodes)
                .exhaustedCodes(exhaustedCodes)
                .revokedCodes(revokedCodes)
                .totalUses(totalUses)
                .averageUsesPerCode(averageUses)
                .build();
    }

    @Override
    public InviteCodeResponseDTO revokeCode(Long id) {
        logger.info("🚫 Revocando código de invitación ID: {}", id);

        InviteCode inviteCode = inviteCodeRepository.findById(id)
                .orElseThrow(
                        () -> new ResourceNotFoundException("Código de invitación no encontrado", "InviteCode", id));

        inviteCode.revoke();
        InviteCode updated = inviteCodeRepository.save(inviteCode);

        logger.info("✅ Código revocado: {}", updated.getCode());

        return mapToResponseDTO(updated);
    }

    @Override
    public int manualCleanup() {
        logger.info("🧹 Ejecutando limpieza manual de códigos expirados...");

        LocalDateTime now = LocalDateTime.now();

        // Marcar códigos expirados
        List<InviteCode> expiredCodes = findExpiredCodes();
        expiredCodes.forEach(code -> code.setStatus(InviteStatus.EXPIRED));
        inviteCodeRepository.saveAll(expiredCodes);
        int markedExpired = expiredCodes.size();

        // Eliminar códigos muy antiguos
        LocalDateTime cutoff = now.minusDays(30);
        List<InviteCode> oldExpiredCodes = inviteCodeRepository.findByStatusAndCreatedAtBefore(InviteStatus.EXPIRED,
                cutoff);
        inviteCodeRepository.deleteAll(oldExpiredCodes);
        int deletedOld = oldExpiredCodes.size();

        int totalCleaned = markedExpired + deletedOld;

        logger.info("✅ Limpieza manual completada: {} marcados como expirados, {} eliminados", markedExpired,
                deletedOld);

        return totalCleaned;
    }

    @Override
    @Transactional(readOnly = true)
    public Page<InviteCodeResponseDTO> getCodesByStatus(String status, Pageable pageable) {
        logger.debug("🔍 Buscando códigos por estado: {} con paginación", status);

        try {
            InviteStatus inviteStatus = InviteStatus.valueOf(status.toUpperCase());
            return inviteCodeRepository.findByStatus(inviteStatus, pageable)
                    .map(this::mapToResponseDTO);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Estado inválido: " + status);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Page<InviteCodeResponseDTO> getMostUsedCodes(Pageable pageable) {
        logger.debug("🔍 Buscando códigos más usados con paginación");

        return inviteCodeRepository.findByCurrentUsesGreaterThanOrderByCurrentUsesDesc(0, pageable)
                .map(this::mapToResponseDTO);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<InviteCodeResponseDTO> searchCodes(String searchTerm, Pageable pageable) {
        logger.debug("🔍 Buscando códigos con término: {} con paginación", searchTerm);

        // Implementación básica de búsqueda
        if (searchTerm == null || searchTerm.trim().isEmpty()) {
            return getAllCodes(pageable);
        }

        // Por ahora, devolvemos todos los códigos
        // TODO: Implementar búsqueda real en el repositorio si es necesario
        return inviteCodeRepository.findAllByOrderByCreatedAtDesc(pageable)
                .map(this::mapToResponseDTO);
    }

    // ✅ LIMPIEZA PROGRAMADA - SIN @Transactional PARA EVITAR CONFLICTOS
    @Scheduled(fixedRate = 3600000) // Cada hora
    public void scheduledCleanupExpiredCodes() {
        logger.debug("🧹 Iniciando limpieza automática de códigos expirados...");

        try {
            // Usar ApplicationContext para obtener el proxy del servicio
            InviteCodeService self = applicationContext.getBean(InviteCodeService.class);
            int cleaned = self.manualCleanup();
            if (cleaned > 0) {
                logger.info("🧹 Limpieza automática: {} códigos procesados", cleaned);
            }
        } catch (Exception e) {
            logger.error("❌ Error en limpieza automática: {}", e.getMessage());
        }
    }

    // ===================================================
    // MÉTODOS PRIVADOS DE UTILIDAD
    // ===================================================

    private Optional<InviteCode> findValidByCode(String code) {
        Optional<InviteCode> inviteCode = inviteCodeRepository.findByCodeAndStatus(code, InviteStatus.ACTIVE);

        if (inviteCode.isEmpty()) {
            return Optional.empty();
        }

        InviteCode invite = inviteCode.get();
        LocalDateTime now = LocalDateTime.now();

        // Verificar si está expirado
        if (invite.getExpiresAt().isBefore(now)) {
            return Optional.empty();
        }

        // Verificar si ya alcanzó el máximo de usos
        if (invite.getMaxUses() != null && invite.getCurrentUses() >= invite.getMaxUses()) {
            return Optional.empty();
        }

        return Optional.of(invite);
    }

    private List<InviteCode> findExpiredCodes() {
        return inviteCodeRepository.findByStatusAndExpiresAtBefore(InviteStatus.ACTIVE, LocalDateTime.now());
    }

    private String generateUniqueCode() {
        String code;
        int attempts = 0;
        do {
            code = generateRandomCode(DEFAULT_CODE_LENGTH);
            attempts++;
            if (attempts > 100) {
                throw new RuntimeException("No se pudo generar código único después de 100 intentos");
            }
        } while (inviteCodeRepository.existsByCode(code));

        return code;
    }

    private String generateUniqueCodeWithPrefix(String prefix) {
        String basePrefix = prefix != null ? prefix.toUpperCase() + "_" : "";
        String code;
        int attempts = 0;

        do {
            code = basePrefix + generateRandomCode(8);
            attempts++;
            if (attempts > 100) {
                throw new RuntimeException("No se pudo generar código único con prefijo después de 100 intentos");
            }
        } while (inviteCodeRepository.existsByCode(code));

        return code;
    }

    private String generateRandomCode(int length) {
        StringBuilder code = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            code.append(CODE_CHARS.charAt(secureRandom.nextInt(CODE_CHARS.length())));
        }
        return code.toString();
    }

    private String validateAndFormatCustomCode(String customCode) {
        String formatted = customCode.toUpperCase().replaceAll("[^A-Z0-9_-]", "");

        if (formatted.length() < 4) {
            throw new BadRequestException("El código personalizado debe tener al menos 4 caracteres");
        }

        if (inviteCodeRepository.existsByCode(formatted)) {
            throw new BadRequestException("El código personalizado ya existe");
        }

        return formatted;
    }

    private String getCurrentUser() {
        try {
            return SecurityContextHolder.getContext().getAuthentication().getName();
        } catch (Exception e) {
            return "system"; // Fallback para inicialización del sistema
        }
    }

    private void validateUserLimits(String user) {
        long activeCodes = inviteCodeRepository.countByCreatedByAndStatus(user, InviteStatus.ACTIVE);

        if (activeCodes >= MAX_ACTIVE_CODES_PER_USER) {
            throw new BadRequestException(
                    "Has alcanzado el límite de códigos activos (" + MAX_ACTIVE_CODES_PER_USER + ")");
        }
    }

    private void validateBulkLimits(String user, int quantity) {
        long activeCodes = inviteCodeRepository.countByCreatedByAndStatus(user, InviteStatus.ACTIVE);

        if (activeCodes + quantity > MAX_ACTIVE_CODES_PER_USER) {
            throw new BadRequestException(
                    "La operación excedería el límite de códigos activos (" + MAX_ACTIVE_CODES_PER_USER + ")");
        }
    }

    private InviteCodeResponseDTO mapToResponseDTO(InviteCode inviteCode) {
        long hoursUntilExpiration = inviteCode.isExpired() ? 0
                : ChronoUnit.HOURS.between(LocalDateTime.now(), inviteCode.getExpiresAt());

        int remainingUses = inviteCode.getMaxUses() != null
                ? Math.max(0, inviteCode.getMaxUses() - inviteCode.getCurrentUses())
                : -1;

        return InviteCodeResponseDTO.builder()
                .id(inviteCode.getId())
                .code(inviteCode.getCode())
                .description(inviteCode.getDescription())
                .status(inviteCode.getStatus().name())
                .statusDisplayName(inviteCode.getStatus().getDisplayName())
                .expiresAt(inviteCode.getExpiresAt())
                .maxUses(inviteCode.getMaxUses())
                .currentUses(inviteCode.getCurrentUses())
                .createdBy(inviteCode.getCreatedBy())
                .usedBy(inviteCode.getUsedBy())
                .createdAt(inviteCode.getCreatedAt())
                .updatedAt(inviteCode.getUpdatedAt())
                .isValid(inviteCode.isValid())
                .isExpired(inviteCode.isExpired())
                .isMaxUsesReached(inviteCode.isMaxUsesReached())
                .hoursUntilExpiration(hoursUntilExpiration)
                .remainingUses(remainingUses)
                .build();
    }
}