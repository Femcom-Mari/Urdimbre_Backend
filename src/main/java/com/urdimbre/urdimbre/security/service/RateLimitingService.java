package com.urdimbre.urdimbre.security.service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterConfig;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;
import lombok.Data;

@Service
public class RateLimitingService {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitingService.class);

    private final RateLimiterRegistry rateLimiterRegistry;
    private final Map<String, RateLimiter> rateLimiters = new ConcurrentHashMap<>();

    @Value("${rate-limit.login.ip.capacity:10}")
    private int loginIpCapacity;

    @Value("${rate-limit.login.ip.refill-duration:PT1M}")
    private Duration loginIpRefillDuration;

    @Value("${rate-limit.login.user.capacity:5}")
    private int loginUserCapacity;

    @Value("${rate-limit.login.user.refill-duration:PT2M}")
    private Duration loginUserRefillDuration;

    @Value("${rate-limit.register.ip.capacity:3}")
    private int registerIpCapacity;

    @Value("${rate-limit.register.ip.refill-duration:PT5M}")
    private Duration registerIpRefillDuration;

    public RateLimitingService() {
        this.rateLimiterRegistry = RateLimiterRegistry.ofDefaults();
    }

    public RateLimitResult checkLoginByIp(HttpServletRequest request) {
        String ip = getClientIp(request);
        String key = "login_ip_" + ip;

        RateLimiter rateLimiter = getOrCreateRateLimiter(key, loginIpCapacity, loginIpRefillDuration);

        boolean allowed = rateLimiter.acquirePermission();

        if (allowed) {
            logger.debug("✅ Rate limit LOGIN por IP OK - IP: {}", ip);
            return new RateLimitResult(true, getRemainingPermissions(rateLimiter), 0);
        } else {
            long retryAfter = loginIpRefillDuration.getSeconds();
            logger.warn("🚫 Rate limit LOGIN por IP EXCEDIDO - IP: {}", ip);
            return new RateLimitResult(false, 0, retryAfter);
        }
    }

    public RateLimitResult checkLoginByUser(String username) {
        String key = "login_user_" + username;

        RateLimiter rateLimiter = getOrCreateRateLimiter(key, loginUserCapacity, loginUserRefillDuration);

        boolean allowed = rateLimiter.acquirePermission();

        if (allowed) {
            logger.debug("✅ Rate limit LOGIN por usuario OK - User: {}", username);
            return new RateLimitResult(true, getRemainingPermissions(rateLimiter), 0);
        } else {
            long retryAfter = loginUserRefillDuration.getSeconds();
            logger.warn("🚫 Rate limit LOGIN por usuario EXCEDIDO - User: {}", username);
            return new RateLimitResult(false, 0, retryAfter);
        }
    }

    public RateLimitResult checkRegisterByIp(HttpServletRequest request) {
        String ip = getClientIp(request);
        String key = "register_ip_" + ip;

        RateLimiter rateLimiter = getOrCreateRateLimiter(key, registerIpCapacity, registerIpRefillDuration);

        boolean allowed = rateLimiter.acquirePermission();

        if (allowed) {
            logger.debug("✅ Rate limit REGISTRO por IP OK - IP: {}", ip);
            return new RateLimitResult(true, getRemainingPermissions(rateLimiter), 0);
        } else {
            long retryAfter = registerIpRefillDuration.getSeconds();
            logger.warn("🚫 Rate limit REGISTRO por IP EXCEDIDO - IP: {}", ip);
            return new RateLimitResult(false, 0, retryAfter);
        }
    }

    public String getClientIp(HttpServletRequest request) {
        String clientIp = request.getHeader("X-Forwarded-For");
        if (clientIp != null && !clientIp.isEmpty() && !"unknown".equalsIgnoreCase(clientIp)) {
            return clientIp.split(",")[0].trim();
        }

        clientIp = request.getHeader("X-Real-IP");
        if (clientIp != null && !clientIp.isEmpty() && !"unknown".equalsIgnoreCase(clientIp)) {
            return clientIp;
        }

        return request.getRemoteAddr();
    }

    public void cleanupOldBuckets() {
        int initialSize = rateLimiters.size();
        rateLimiters.clear();
        logger.info("🧹 Limpieza de rate limiters completada - Removidos: {}", initialSize);
    }

    public RateLimitStats getStatistics() {
        return RateLimitStats.builder()
                .activeBuckets(rateLimiters.size())
                .ipBuckets((int) rateLimiters.keySet().stream().filter(k -> k.contains("_ip_")).count())
                .userBuckets((int) rateLimiters.keySet().stream().filter(k -> k.contains("_user_")).count())
                .registerBuckets((int) rateLimiters.keySet().stream().filter(k -> k.startsWith("register_")).count())
                .build();
    }

    private RateLimiter getOrCreateRateLimiter(String key, int limit, Duration duration) {
        return rateLimiters.computeIfAbsent(key, k -> {
            RateLimiterConfig config = RateLimiterConfig.custom()
                    .limitForPeriod(limit)
                    .limitRefreshPeriod(duration)
                    .timeoutDuration(Duration.ZERO)
                    .build();

            return rateLimiterRegistry.rateLimiter(k, config);
        });
    }

    private long getRemainingPermissions(RateLimiter rateLimiter) {
        return Math.max(0, rateLimiter.getRateLimiterConfig().getLimitForPeriod() - 1);
    }

    @Data
    public static class RateLimitResult {
        private final boolean allowed;
        private final long remainingTokens;
        private final long retryAfterSeconds;
    }

    @Data
    @Builder
    public static class RateLimitStats {
        private final int activeBuckets;
        private final int ipBuckets;
        private final int userBuckets;
        private final int registerBuckets;
    }
}