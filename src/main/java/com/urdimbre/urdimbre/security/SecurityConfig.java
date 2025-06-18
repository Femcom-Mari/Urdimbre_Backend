package com.urdimbre.urdimbre.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.urdimbre.urdimbre.security.filter.JwtAuthorizationFilter;
import com.urdimbre.urdimbre.security.service.UserDetailsServiceImpl;
import com.urdimbre.urdimbre.service.token.RefreshTokenService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

        private static final String ROLE_ADMIN = "ADMIN";
        private static final String ROLE_USER = "USER";
        private static final String PROFESSIONALS_API_PATTERN = "/api/professionals/**";

        private final UserDetailsServiceImpl userDetailsService;
        private final RefreshTokenService refreshTokenService;

        // 🌍 DETECTAR ENTORNO PARA CONFIGURACIONES ESPECÍFICAS
        @Value("${spring.profiles.active:dev}")
        private String activeProfile;

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                log.info("🔒 Configurando Security Filter Chain - VERSIÓN PRODUCCIÓN CON NUEVOS ENDPOINTS");

                http
                                .csrf(csrf -> csrf.disable())
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                                // ================================
                                // ✅ HEADERS DE SEGURIDAD HTTP - PARA SPRING BOOT 3.5
                                // ================================
                                .headers(headers -> headers
                                                // 🛡️ Anti-Clickjacking
                                                .frameOptions(org.springframework.security.config.Customizer
                                                                .withDefaults())

                                                // 🔒 Content Type Protection
                                                .contentTypeOptions(contentTypeOptions -> {
                                                })

                                                // 🛡️ HSTS Protection
                                                .httpStrictTransportSecurity(hstsConfig -> {
                                                        if (isProductionEnvironment()) {
                                                                hstsConfig
                                                                                .maxAgeInSeconds(31536000) // 1 año
                                                                                .includeSubDomains(true)
                                                                                .preload(true);
                                                        }
                                                })

                                                // 🛡️ Content Security Policy
                                                .contentSecurityPolicy(cspConfig -> cspConfig
                                                                .policyDirectives(buildContentSecurityPolicy()))

                                                // ✅ Headers personalizados
                                                .addHeaderWriter((request, response) -> {
                                                        // XSS Protection manual
                                                        response.setHeader("X-XSS-Protection", "1; mode=block");
                                                        // Referrer Policy manual
                                                        response.setHeader("Referrer-Policy",
                                                                        "strict-origin-when-cross-origin");
                                                        // Permissions Policy
                                                        response.setHeader("Permissions-Policy",
                                                                        "geolocation=(), microphone=(), camera=(), " +
                                                                                        "payment=(), usb=(), magnetometer=(), gyroscope=()");
                                                }))

                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                // ================================
                                // ✅ CONFIGURACIÓN DE AUTORIZACIÓN PARA PRODUCCIÓN
                                // ================================
                                .authorizeHttpRequests(auth -> auth
                                                // ================================
                                                // ✅ ENDPOINTS PÚBLICOS (sin autenticación)
                                                // ================================
                                                .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/api/auth/refresh").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/api/auth/forgot-password")
                                                .permitAll() // ✅ NUEVO
                                                .requestMatchers(HttpMethod.GET, "/api/auth/check-username").permitAll() // ✅
                                                                                                                         // NUEVO
                                                .requestMatchers(HttpMethod.GET, "/api/auth/check-email").permitAll() // ✅
                                                                                                                      // NUEVO
                                                .requestMatchers(HttpMethod.GET, "/api/auth/invite-codes/validate")
                                                .permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/auth/invite-codes/info")
                                                .permitAll()
                                                .requestMatchers("/actuator/health").permitAll()
                                                .requestMatchers("/actuator/info").permitAll()
                                                .requestMatchers("/error").permitAll()

                                                // ================================
                                                // 🔧 ENDPOINTS DE DESARROLLO - CONDICIONALES
                                                // Solo activos en entorno de desarrollo
                                                // ================================
                                                .requestMatchers("/api/dev/**").access((authentication, context) -> {
                                                        boolean isDev = "dev".equals(activeProfile) ||
                                                                        "development".equals(activeProfile) ||
                                                                        "local".equals(activeProfile);

                                                        if (!isDev) {
                                                                log.warn("🚫 Intento de acceso a endpoint de desarrollo en entorno: {}",
                                                                                activeProfile);
                                                        }

                                                        return new org.springframework.security.authorization.AuthorizationDecision(
                                                                        isDev);
                                                })
                                                .requestMatchers("/actuator/dev/**")
                                                .access(this::isDevelopmentEnvironment)
                                                .requestMatchers("/api/test/**").access(this::isDevelopmentEnvironment)

                                                // ================================
                                                // ✅ ENDPOINTS DE ADMIN (requieren rol ADMIN)
                                                // ================================
                                                .requestMatchers("/api/admin/**").hasRole(ROLE_ADMIN)
                                                .requestMatchers("/api/roles/**").hasRole(ROLE_ADMIN)
                                                .requestMatchers("/api/auth/rate-limit-stats").hasRole(ROLE_ADMIN) // ✅
                                                                                                                   // Solo
                                                                                                                   // admin

                                                // ================================
                                                // ✅ PROFESSIONALS ENDPOINTS
                                                // ================================
                                                // Professional endpoints - read access for users and admins
                                                .requestMatchers(HttpMethod.GET, "/api/professionals")
                                                .hasAnyRole(ROLE_USER, ROLE_ADMIN)
                                                .requestMatchers(HttpMethod.GET, PROFESSIONALS_API_PATTERN)
                                                .hasAnyRole(ROLE_USER, ROLE_ADMIN)

                                                // Professional endpoints - write access only for admins
                                                .requestMatchers(HttpMethod.POST, "/api/professionals")
                                                .hasRole(ROLE_ADMIN)
                                                .requestMatchers(HttpMethod.PUT, PROFESSIONALS_API_PATTERN)
                                                .hasRole(ROLE_ADMIN)
                                                .requestMatchers(HttpMethod.PATCH, PROFESSIONALS_API_PATTERN)
                                                .hasRole(ROLE_ADMIN)
                                                .requestMatchers(HttpMethod.DELETE, PROFESSIONALS_API_PATTERN)
                                                .hasRole(ROLE_ADMIN)

                                                // ================================
                                                // ✅ ENDPOINTS AUTENTICADOS (requieren login)
                                                // ================================
                                                .requestMatchers(HttpMethod.POST, "/api/auth/logout").authenticated()
                                                .requestMatchers("/api/users/**").authenticated()

                                                // ================================
                                                // ✅ RESTO DE ENDPOINTS (DEBE SER EL ÚLTIMO)
                                                // ================================
                                                .anyRequest().authenticated())

                                .addFilterBefore(
                                                new JwtAuthorizationFilter(userDetailsService, refreshTokenService),
                                                UsernamePasswordAuthenticationFilter.class);

                log.info("✅ Security Filter Chain configurado para PRODUCCIÓN con nuevos endpoints de auth y protección condicional de dev");
                return http.build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                log.info("🌐 Configurando CORS con headers de seguridad para producción");

                CorsConfiguration configuration = new CorsConfiguration();

                // ================================
                // ✅ ORÍGENES PERMITIDOS (configuración para producción)
                // ================================
                if (isProductionEnvironment()) {
                        // 🚀 PRODUCCIÓN: Solo dominios específicos
                        configuration.addAllowedOriginPattern("https://tu-dominio.com");
                        configuration.addAllowedOriginPattern("https://*.tu-dominio.com");
                        configuration.addAllowedOriginPattern("https://app.tu-dominio.com");
                        log.info("🔒 CORS configurado para PRODUCCIÓN - solo HTTPS permitido");
                } else {
                        // 🔧 DESARROLLO: Localhost en cualquier puerto
                        configuration.addAllowedOriginPattern("http://localhost:*");
                        configuration.addAllowedOriginPattern("http://127.0.0.1:*");
                        configuration.addAllowedOriginPattern("http://[::1]:*");
                        log.info("🔧 CORS configurado para DESARROLLO - localhost permitido");
                }

                // Allowed methods
                configuration.addAllowedMethod("GET");
                configuration.addAllowedMethod("POST");
                configuration.addAllowedMethod("PUT");
                configuration.addAllowedMethod("PATCH");
                configuration.addAllowedMethod("DELETE");
                configuration.addAllowedMethod("OPTIONS");
                configuration.addAllowedMethod("HEAD");

                // Allowed headers
                configuration.addAllowedHeader("*");

                // Exposed headers - incluye los nuevos para rate limiting
                configuration.addExposedHeader("Authorization");
                configuration.addExposedHeader("Refresh-Token");
                configuration.addExposedHeader("Content-Length");
                configuration.addExposedHeader("Content-Type");
                configuration.addExposedHeader("Retry-After"); // ✅ Para rate limiting
                configuration.addExposedHeader("X-RateLimit-Type"); // ✅ Para rate limiting
                configuration.addExposedHeader("X-RateLimit-Remaining"); // ✅ Para rate limiting
                configuration.addExposedHeader("X-RateLimit-IP-Remaining"); // ✅ Para rate limiting
                configuration.addExposedHeader("X-RateLimit-User-Remaining"); // ✅ Para rate limiting

                // Additional configurations
                configuration.setAllowCredentials(true);
                configuration.setMaxAge(3600L);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);

                log.info("✅ CORS configurado correctamente para entorno: {}", activeProfile);
                return source;
        }

        @Bean
        public HttpFirewall httpFirewall() {
                log.info("🛡️ Configurando HTTP Firewall con seguridad máxima para producción");

                StrictHttpFirewall firewall = new StrictHttpFirewall();

                // ================================
                // ✅ CONFIGURACIONES DE SEGURIDAD ESTRICTAS
                // ================================
                firewall.setAllowUrlEncodedCarriageReturn(false); // Prevenir CRLF injection
                firewall.setAllowUrlEncodedPercent(true); // Necesario para query params
                firewall.setAllowUrlEncodedSlash(false); // Prevenir path traversal
                firewall.setAllowUrlEncodedPeriod(false); // Prevenir directory traversal
                firewall.setAllowBackSlash(false); // Prevenir Windows path traversal
                firewall.setAllowUrlEncodedLineFeed(false); // Prevenir line feed injection
                firewall.setAllowSemicolon(false); // Prevenir parameter pollution
                firewall.setAllowUrlEncodedDoubleSlash(false); // Prevenir path manipulation

                // ================================
                // ✅ CARACTERES BLOQUEADOS ADICIONALES
                // ================================
                firewall.setAllowNull(false); // Bloquear caracteres null

                log.info("✅ HTTP Firewall configurado con protección máxima contra ataques de seguridad");
                return firewall;
        }

        @Bean
        public WebSecurityCustomizer webSecurityCustomizer() {
                return web -> web.httpFirewall(httpFirewall());
        }

        @Bean
        public BCryptPasswordEncoder bCryptPasswordEncoder() {
                log.debug("🔐 Creando bean BCryptPasswordEncoder con strength 12 para producción");
                return new BCryptPasswordEncoder(12); // Strength 12 para mayor seguridad
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                log.debug("🔐 Creando bean PasswordEncoder con strength 12 para producción");
                return new BCryptPasswordEncoder(12); // Strength 12 para mayor seguridad
        }

        // ================================
        // ✅ MÉTODOS PRIVADOS PARA CONFIGURACIÓN
        // ================================

        /**
         * 🌍 Verificar si estamos en entorno de producción
         */
        private boolean isProductionEnvironment() {
                return "prod".equals(activeProfile) ||
                                "production".equals(activeProfile) ||
                                "prd".equals(activeProfile);
        }

        /**
         * Verificar si estamos en entorno de desarrollo (para endpoints
         * condicionales)
         */
        private org.springframework.security.authorization.AuthorizationDecision isDevelopmentEnvironment(
                        java.util.function.Supplier<org.springframework.security.core.Authentication> authentication,
                        org.springframework.security.web.access.intercept.RequestAuthorizationContext context) {

                boolean isDev = "dev".equals(activeProfile) ||
                                "development".equals(activeProfile) ||
                                "local".equals(activeProfile);

                if (!isDev) {
                        log.warn("🚫 Intento de acceso a endpoint de desarrollo en entorno: {}", activeProfile);
                }

                return new org.springframework.security.authorization.AuthorizationDecision(isDev);
        }

        /**
         * Construir Content Security Policy según el entorno
         */
        private String buildContentSecurityPolicy() {
                if (isProductionEnvironment()) {
                        // CSP ESTRICTO PARA PRODUCCIÓN
                        return "default-src 'self'; " +
                                        "script-src 'self'; " +
                                        "style-src 'self' 'unsafe-inline'; " +
                                        "img-src 'self' data: https:; " +
                                        "font-src 'self'; " +
                                        "connect-src 'self'; " +
                                        "frame-ancestors 'none'; " +
                                        "form-action 'self'; " +
                                        "base-uri 'self'; " +
                                        "object-src 'none'; " +
                                        "upgrade-insecure-requests";
                } else {
                        // CSP MÁS PERMISIVO PARA DESARROLLO
                        return "default-src 'self'; " +
                                        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
                                        "style-src 'self' 'unsafe-inline'; " +
                                        "img-src 'self' data: https: http:; " +
                                        "font-src 'self'; " +
                                        "connect-src 'self' http://localhost:* ws://localhost:* wss://localhost:*; " +
                                        "frame-ancestors 'none'; " +
                                        "form-action 'self'; " +
                                        "base-uri 'self'; " +
                                        "object-src 'none'";
                }
        }
}