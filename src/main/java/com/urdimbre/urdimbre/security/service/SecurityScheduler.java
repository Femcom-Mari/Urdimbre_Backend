package com.urdimbre.urdimbre.security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.service.invite.InviteCodeService;
import com.urdimbre.urdimbre.service.token.BlacklistedTokenService;
import com.urdimbre.urdimbre.service.token.RefreshTokenService;

import lombok.RequiredArgsConstructor;

@Service
@EnableScheduling
@RequiredArgsConstructor
@ConditionalOnProperty(value = "token.cleanup.enabled", havingValue = "true", matchIfMissing = true)
public class SecurityScheduler {

    private static final Logger logger = LoggerFactory.getLogger(SecurityScheduler.class);

    private final BlacklistedTokenService blacklistedTokenService;
    private final RefreshTokenService refreshTokenService;
    private final RateLimitingService rateLimitingService;
    private final InviteCodeService inviteCodeService;

    @Value("${spring.profiles.active:dev}")
    private String activeProfile;

    @Scheduled(fixedRateString = "${token.cleanup.interval:3600000}")
    public void cleanupExpiredTokens() {
        try {
            logger.debug("🧹 Iniciando limpieza automática de tokens expirados...");

            BlacklistedTokenService.BlacklistStats beforeBlacklist = blacklistedTokenService.getStatistics();
            blacklistedTokenService.cleanupExpiredTokens();
            BlacklistedTokenService.BlacklistStats afterBlacklist = blacklistedTokenService.getStatistics();

            refreshTokenService.cleanupExpiredTokens();

            int expiredCodes = inviteCodeService.manualCleanup();

            long blacklistCleaned = beforeBlacklist.getTotalBlacklistedTokens()
                    - afterBlacklist.getTotalBlacklistedTokens();

            logger.info("🧹 Limpieza automática completada - Blacklist: {} tokens, Códigos: {} códigos",
                    blacklistCleaned, expiredCodes);

        } catch (Exception e) {
            logger.error("❌ Error durante limpieza automática de tokens: {}", e.getMessage(), e);
        }
    }

    @Scheduled(fixedRateString = "${rate-limit.cleanup.interval:1800000}")
    public void cleanupRateLimitingBuckets() {
        try {
            logger.debug("🗄️ Iniciando limpieza de buckets de rate limiting...");

            RateLimitingService.RateLimitStats beforeStats = rateLimitingService.getStatistics();
            rateLimitingService.cleanupOldBuckets();
            RateLimitingService.RateLimitStats afterStats = rateLimitingService.getStatistics();

            int bucketsRemoved = beforeStats.getActiveBuckets() - afterStats.getActiveBuckets();

            if (bucketsRemoved > 0) {
                logger.info("🗄️ Limpieza de rate limiting completada - {} buckets removidos", bucketsRemoved);
            }

        } catch (Exception e) {
            logger.error("❌ Error durante limpieza de rate limiting: {}", e.getMessage(), e);
        }
    }

    @Scheduled(fixedRate = 21600000)
    @ConditionalOnProperty(value = "spring.profiles.active", havingValue = "dev")
    public void logSecurityStatistics() {
        try {
            if (!"dev".equals(activeProfile)) {
                return; // Solo en desarrollo
            }

            logger.info("📊 === ESTADÍSTICAS DE SEGURIDAD ===");

            BlacklistedTokenService.BlacklistStats blacklistStats = blacklistedTokenService.getStatistics();
            logger.info("🚫 Blacklist - Total: {}",
                    blacklistStats.getTotalBlacklistedTokens());

            RateLimitingService.RateLimitStats rateLimitStats = rateLimitingService.getStatistics();
            logger.info("🗄️ Rate Limiting - Buckets activos: {}, IP: {}, User: {}, Register: {}",
                    rateLimitStats.getActiveBuckets(),
                    rateLimitStats.getIpBuckets(),
                    rateLimitStats.getUserBuckets(),
                    rateLimitStats.getRegisterBuckets());

            logger.info("📊 === FIN ESTADÍSTICAS ===");

        } catch (Exception e) {
            logger.warn("⚠️ Error generando estadísticas de seguridad: {}", e.getMessage());
        }
    }

    @Scheduled(fixedRate = 300000)
    public void securityHealthCheck() {
        try {

            BlacklistedTokenService.BlacklistStats blacklistStats = blacklistedTokenService.getStatistics();
            RateLimitingService.RateLimitStats rateLimitStats = rateLimitingService.getStatistics();

            if (blacklistStats.getTotalBlacklistedTokens() > 10000) {
                logger.warn("⚠️ Blacklist muy grande: {} tokens", blacklistStats.getTotalBlacklistedTokens());
            }

            if (rateLimitStats.getActiveBuckets() > 1000) {
                logger.warn("⚠️ Muchos buckets de rate limiting activos: {}", rateLimitStats.getActiveBuckets());
            }

            logger.debug("❤️ Security health check passed - Blacklist: {}, Rate buckets: {}",
                    blacklistStats.getTotalBlacklistedTokens(),
                    rateLimitStats.getActiveBuckets());

        } catch (Exception e) {
            logger.error("💔 Security health check failed: {}", e.getMessage());
        }
    }
}