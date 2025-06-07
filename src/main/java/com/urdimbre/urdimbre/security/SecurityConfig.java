package com.urdimbre.urdimbre.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
@EnableMethodSecurity(prePostEnabled = true) // ✅ NECESARIO para @PreAuthorize en controllers
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

        private final UserDetailsServiceImpl userDetailsService;
        private final RefreshTokenService refreshTokenService;

        // 🌍 DETECTAR ENTORNO PARA CONFIGURACIONES ESPECÍFICAS
        @Value("${spring.profiles.active:dev}")
        private String activeProfile;

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                log.info("🔒 Configurando Security Filter Chain - VERSIÓN FINAL SEGURA + HEADERS HTTP");

                http
                                .csrf(csrf -> csrf.disable())
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                                // ================================
                                // ✅ HEADERS DE SEGURIDAD HTTP - CORREGIDO PARA SPRING BOOT 3.5
                                // ================================
                                .headers(headers -> headers
                                                // 🛡️ Anti-Clickjacking
                                                .frameOptions(frameOptions -> frameOptions.deny())

                                                // 🔒 Content Type Protection
                                                .contentTypeOptions(contentTypeOptions -> {
                                                })

                                                // 🛡️ XSS Protection - SINTAXIS CORREGIDA
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
                                                // ✅ Add custom header writer here
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

                                .authorizeHttpRequests(auth -> auth

                                                // ================================
                                                // ✅ ENDPOINTS PÚBLICOS (sin autenticación)
                                                // ================================
                                                .requestMatchers(
                                                                "/api/auth/login",
                                                                "/api/auth/register",
                                                                "/api/auth/refresh",
                                                                "/api/auth/invite-codes/validate", // ✅ NUEVO
                                                                "/api/auth/invite-codes/info", // ✅ NUEVO
                                                                "/actuator/health",
                                                                "/error")
                                                .permitAll()

                                                // ================================
                                                // ✅ ENDPOINTS DE ADMIN (requieren rol ADMIN)
                                                // ================================
                                                .requestMatchers("/api/admin/**")
                                                .hasRole("ADMIN")

                                                // ================================
                                                // ✅ ENDPOINTS AUTENTICADOS (requieren login)
                                                // ================================
                                                .requestMatchers("/api/auth/logout").authenticated()
                                                .requestMatchers("/api/users/**").authenticated()
                                                .requestMatchers("/api/roles/**").hasRole("ADMIN")

                                                // ================================
                                                // ✅ RESTO DE ENDPOINTS (requieren autenticación)
                                                // ================================
                                                .anyRequest().authenticated())

                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                .addFilterBefore(
                                                new JwtAuthorizationFilter(userDetailsService, refreshTokenService),
                                                UsernamePasswordAuthenticationFilter.class);

                log.info("✅ Security Filter Chain SEGURO configurado con headers HTTP avanzados y códigos de invitación");
                return http.build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                log.info("🌐 Configurando CORS con headers de seguridad");

                CorsConfiguration configuration = new CorsConfiguration();

                // ================================
                // ✅ ORÍGENES PERMITIDOS (ajusta según tu entorno)
                // ================================
                if (isProductionEnvironment()) {
                        // 🚀 PRODUCCIÓN: Solo dominios específicos
                        configuration.addAllowedOriginPattern("https://tu-dominio.com");
                        configuration.addAllowedOriginPattern("https://*.tu-dominio.com");
                        configuration.addAllowedOriginPattern("https://app.tu-dominio.com");
                } else {
                        // 🔧 DESARROLLO: Localhost en cualquier puerto
                        configuration.addAllowedOriginPattern("http://localhost:*");
                        configuration.addAllowedOriginPattern("http://127.0.0.1:*");
                        configuration.addAllowedOriginPattern("http://[::1]:*");
                }

                // ================================
                // ✅ MÉTODOS HTTP PERMITIDOS
                // ================================
                configuration.addAllowedMethod("GET");
                configuration.addAllowedMethod("POST");
                configuration.addAllowedMethod("PUT");
                configuration.addAllowedMethod("PATCH");
                configuration.addAllowedMethod("DELETE");
                configuration.addAllowedMethod("OPTIONS");
                configuration.addAllowedMethod("HEAD");

                // ================================
                // ✅ HEADERS PERMITIDOS
                // ================================
                configuration.addAllowedHeader("*");

                // ================================
                // ✅ HEADERS EXPUESTOS (para que el frontend pueda leerlos)
                // ================================
                configuration.addExposedHeader("Authorization");
                configuration.addExposedHeader("Refresh-Token");
                configuration.addExposedHeader("Content-Length");
                configuration.addExposedHeader("Content-Type");
                configuration.addExposedHeader("Retry-After"); // ✅ NUEVO: Para rate limiting
                configuration.addExposedHeader("X-RateLimit-Type"); // ✅ NUEVO: Para rate limiting
                configuration.addExposedHeader("X-RateLimit-Remaining"); // ✅ NUEVO: Para rate limiting
                configuration.addExposedHeader("X-RateLimit-IP-Remaining"); // ✅ NUEVO: Para rate limiting
                configuration.addExposedHeader("X-RateLimit-User-Remaining"); // ✅ NUEVO: Para rate limiting

                // ================================
                // ✅ CONFIGURACIONES ADICIONALES
                // ================================
                // Permitir credentials (cookies, headers de autorización)
                configuration.setAllowCredentials(true);

                // Tiempo de cache para preflight requests (1 hora)
                configuration.setMaxAge(3600L);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);

                log.info("✅ CORS configurado correctamente para entorno: {}", activeProfile);
                return source;
        }

        @Bean
        public HttpFirewall httpFirewall() {
                log.info("🛡️ Configurando HTTP Firewall con seguridad máxima");

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

                log.info("✅ HTTP Firewall configurado con protección máxima contra path traversal y injection");
                return firewall;
        }

        @Bean
        public WebSecurityCustomizer webSecurityCustomizer() {
                return (web) -> web.httpFirewall(httpFirewall());
        }

        // ================================
        // ✅ BEANS DE CODIFICACIÓN DE CONTRASEÑAS
        // ================================

        /**
         * Bean específico BCryptPasswordEncoder para inyección directa
         */
        @Bean
        public BCryptPasswordEncoder bCryptPasswordEncoder() {
                log.debug("🔐 Creando bean BCryptPasswordEncoder con strength 12");
                return new BCryptPasswordEncoder(12); // Strength 12 para mayor seguridad
        }

        /**
         * Bean PasswordEncoder para compatibilidad con Spring Security
         */
        @Bean
        public PasswordEncoder passwordEncoder() {
                log.debug("🔐 Creando bean PasswordEncoder con strength 12");
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
         * 🛡️ Construir Content Security Policy según el entorno
         */
        private String buildContentSecurityPolicy() {
                if (isProductionEnvironment()) {
                        // 🚀 CSP ESTRICTO PARA PRODUCCIÓN
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
                        // 🔧 CSP MÁS PERMISIVO PARA DESARROLLO
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
