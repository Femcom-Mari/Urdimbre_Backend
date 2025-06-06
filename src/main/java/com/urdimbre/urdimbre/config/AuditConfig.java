package com.urdimbre.urdimbre.config;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class AuditConfig {

    private static final Logger logger = LoggerFactory.getLogger(AuditConfig.class);

    /**
     * 👤 Proveedor de auditores para campos createdBy/lastModifiedBy
     * (BCryptPasswordEncoder se define en SecurityConfig, no aquí)
     */
    @Bean
    public AuditorAware<String> auditorProvider() {
        logger.info("👤 Configurando AuditorAware para auditoría automática");
        return new SpringSecurityAuditorAware();
    }

    /**
     * 🎯 Implementación personalizada del AuditorAware
     */
    public static class SpringSecurityAuditorAware implements AuditorAware<String> {

        private static final Logger logger = LoggerFactory.getLogger(SpringSecurityAuditorAware.class);

        @Override
        @org.springframework.lang.NonNull
        public Optional<String> getCurrentAuditor() {
            try {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

                if (authentication == null) {
                    logger.debug("👤 No hay autenticación activa, usando 'system'");
                    return Optional.of("system");
                }

                if (!authentication.isAuthenticated()) {
                    logger.debug("👤 Usuario no autenticado, usando 'anonymous'");
                    return Optional.of("anonymous");
                }

                String username = authentication.getName();
                if ("anonymousUser".equals(username)) {
                    logger.debug("👤 Usuario anónimo detectado, usando 'anonymous'");
                    return Optional.of("anonymous");
                }

                logger.debug("👤 Usuario actual para auditoría: {}", username);
                return Optional.of(username);

            } catch (Exception e) {
                logger.warn("⚠️ Error obteniendo usuario actual para auditoría: {}", e.getMessage());
                return Optional.of("system");
            }
        }
    }
}