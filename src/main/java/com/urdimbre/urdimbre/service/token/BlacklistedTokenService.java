package com.urdimbre.urdimbre.service.token;

import java.time.LocalDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.urdimbre.urdimbre.model.BlacklistedToken;
import com.urdimbre.urdimbre.repository.BlacklistedTokenRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class BlacklistedTokenService {

    private static final Logger logger = LoggerFactory.getLogger(BlacklistedTokenService.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    private final BlacklistedTokenRepository blacklistedTokenRepository;

    @Transactional
    public void blacklistToken(String tokenId, String username, String tokenType, LocalDateTime expiresAt,
            String reason) {

        saveBlacklistedToken(tokenId, username, tokenType, expiresAt, reason);
    }

    @Transactional
    public void blacklistToken(String fullToken, String reason) {
        try {

            Algorithm algorithm = Algorithm.HMAC512(jwtSecret);
            DecodedJWT jwt = JWT.require(algorithm).build().verify(fullToken);

            String tokenId = generateTokenId(fullToken);
            String username = jwt.getSubject();
            String tokenType = jwt.getClaim("type").asString();
            if (tokenType == null) {
                tokenType = "unknown";
            }

            LocalDateTime expiresAt = jwt.getExpiresAt() != null
                    ? jwt.getExpiresAt().toInstant().atZone(java.time.ZoneId.systemDefault()).toLocalDateTime()
                    : LocalDateTime.now().plusDays(1);

            saveBlacklistedToken(tokenId, username, tokenType, expiresAt, reason);

        } catch (Exception e) {
            logger.warn("⚠️ Error decodificando token para blacklist: {}", e.getMessage());

            String tokenId = generateTokenId(fullToken);
            saveBlacklistedToken(tokenId, "unknown", "unknown", LocalDateTime.now().plusDays(1),
                    reason + " (error decoding)");
        }
    }

    @Transactional(readOnly = true)
    public boolean isTokenBlacklisted(String tokenId) {
        return blacklistedTokenRepository.existsByTokenId(tokenId);
    }

    @Transactional(readOnly = true)
    public boolean isFullTokenBlacklisted(String fullToken) {
        String tokenId = generateTokenId(fullToken);
        return blacklistedTokenRepository.existsByTokenId(tokenId);
    }

    @Transactional
    public void blacklistAllUserTokens(String username, String reason) {
        try {
            blacklistedTokenRepository.deleteAllByUsername(username);
            logger.info("🗑️ Todos los tokens invalidados para usuario: {} (razón: {})", username, reason);
        } catch (Exception e) {
            logger.error("❌ Error invalidando tokens para usuario {}: {}", username, e.getMessage());
        }
    }

    @Scheduled(fixedRate = 3600000) // 3600000 ms = 1 hora
    @Transactional
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();

        try {
            long initialCount = blacklistedTokenRepository.count();
            blacklistedTokenRepository.deleteExpiredTokens(now);
            long finalCount = blacklistedTokenRepository.count();

            long deletedCount = initialCount - finalCount;
            if (deletedCount > 0) {
                logger.info("🧹 Limpieza completada: {} tokens expirados eliminados de blacklist", deletedCount);
            } else {
                logger.debug("🧹 Limpieza de blacklist: sin tokens expirados para eliminar");
            }
        } catch (Exception e) {
            logger.error("❌ Error en limpieza de tokens expirados: {}", e.getMessage());
        }
    }

    @Transactional
    public long manualCleanup() {
        LocalDateTime now = LocalDateTime.now();

        try {
            long initialCount = blacklistedTokenRepository.count();
            blacklistedTokenRepository.deleteExpiredTokens(now);
            long finalCount = blacklistedTokenRepository.count();

            long deletedCount = initialCount - finalCount;
            logger.info("🧹 Limpieza manual completada: {} tokens eliminados", deletedCount);
            return deletedCount;
        } catch (Exception e) {
            logger.error("❌ Error en limpieza manual: {}", e.getMessage());
            return 0;
        }
    }

    @Transactional(readOnly = true)
    public BlacklistStats getStatistics() {
        try {
            long totalTokens = blacklistedTokenRepository.count();
            LocalDateTime now = LocalDateTime.now();

            return BlacklistStats.builder()
                    .totalBlacklistedTokens(totalTokens)
                    .cleanupExecutions(1L)
                    .lastCleanup(now)
                    .build();
        } catch (Exception e) {
            logger.error("❌ Error obteniendo estadísticas de blacklist: {}", e.getMessage());
            return BlacklistStats.builder()
                    .totalBlacklistedTokens(0L)
                    .cleanupExecutions(0L)
                    .lastCleanup(LocalDateTime.now())
                    .build();
        }
    }

    @Transactional(readOnly = true)
    public boolean findBlacklistedToken(String tokenId) {
        return blacklistedTokenRepository.findByTokenId(tokenId).isPresent();
    }

    private void saveBlacklistedToken(String tokenId, String username, String tokenType,
            LocalDateTime expiresAt, String reason) {

        if (blacklistedTokenRepository.existsByTokenId(tokenId)) {
            logger.debug("Token ya está en blacklist: {}", tokenId);
            return;
        }

        BlacklistedToken blacklistedToken = BlacklistedToken.builder()
                .tokenId(tokenId)
                .username(username)
                .tokenType(tokenType)
                .expiresAt(expiresAt)
                .reason(reason)
                .build();

        blacklistedTokenRepository.save(blacklistedToken);
        String tokenIdShort = tokenId != null && tokenId.length() > 10
                ? tokenId.substring(0, 10) + "..."
                : tokenId;
        logger.info("🚫 Token agregado a blacklist: {} para usuario: {} (razón: {})",
                tokenIdShort, username, reason);
    }

    private String generateTokenId(String fullToken) {
        if (fullToken == null || fullToken.length() < 10) {
            return "invalid_token_" + System.currentTimeMillis();
        }

        String start = fullToken.substring(0, Math.min(fullToken.length(), 8));
        String end = fullToken.substring(Math.max(0, fullToken.length() - 8));
        int hash = fullToken.hashCode();

        return start + "_" + end + "_" + hash;
    }

    @lombok.Builder
    @lombok.Data
    public static class BlacklistStats {
        private long totalBlacklistedTokens;
        private long cleanupExecutions;
        private LocalDateTime lastCleanup;
    }
}