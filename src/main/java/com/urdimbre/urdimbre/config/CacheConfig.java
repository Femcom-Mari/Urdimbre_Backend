package com.urdimbre.urdimbre.config;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.benmanes.caffeine.cache.Caffeine;

@Configuration
@EnableCaching
public class CacheConfig {

    private static final Logger logger = LoggerFactory.getLogger(CacheConfig.class);

    /**
     * 🗄️ Configurar cache manager para rate limiting
     */
    @Bean
    public CacheManager cacheManager() {
        logger.info("🗄️ Configurando Cache Manager para Rate Limiting");

        CaffeineCacheManager cacheManager = new CaffeineCacheManager();

        // ⚡ CONFIGURACIÓN OPTIMIZADA PARA RATE LIMITING
        cacheManager.setCaffeine(Caffeine.newBuilder()
                .maximumSize(10_000) // Máximo 10,000 entradas
                .expireAfterAccess(10, TimeUnit.MINUTES) // Expirar después de 10 minutos sin acceso
                .expireAfterWrite(30, TimeUnit.MINUTES) // Expirar después de 30 minutos desde escritura
                .recordStats() // Habilitar estadísticas
        );

        // 📊 CACHES ESPECÍFICOS - CORREGIDO PARA SPRING BOOT 3.5
        cacheManager.setCacheNames(List.of("rateLimitBuckets", "inviteCodes", "userSessions"));

        logger.info("✅ Cache Manager configurado exitosamente para Rate Limiting");
        logger.info("📊 Max size: 10,000 entries, TTL: 10min access / 30min write");

        return cacheManager;
    }
}