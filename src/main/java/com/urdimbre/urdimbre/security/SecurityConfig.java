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
                                // ✅ ÚNICA CONFIGURACIÓN DE AUTORIZACIÓN (SIN DUPLICADOS)
                                // ================================
                                .authorizeHttpRequests(auth -> auth
                                                // ================================
                                                // ✅ ENDPOINTS PÚBLICOS (sin autenticación)
                                                // ================================
                                                .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/api/auth/refresh").permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/auth/invite-codes/validate")
                                                .permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/auth/invite-codes/info")
                                                .permitAll()
                                                .requestMatchers("/actuator/health").permitAll()
                                                .requestMatchers("/error").permitAll()
                                                .requestMatchers("/api/test/**").permitAll() // Remove in production

                                                // ================================
                                                // ✅ ENDPOINTS DE ADMIN (requieren rol ADMIN)
                                                // ================================
                                                .requestMatchers("/api/admin/**").hasRole(ROLE_ADMIN)
                                                .requestMatchers("/api/roles/**").hasRole(ROLE_ADMIN)

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

                // Exposed headers
                configuration.addExposedHeader("Authorization");
                configuration.addExposedHeader("Refresh-Token");
                configuration.addExposedHeader("Content-Length");
                configuration.addExposedHeader("Content-Type");
                configuration.addExposedHeader("Retry-After"); // ✅ NUEVO: Para rate limiting
                configuration.addExposedHeader("X-RateLimit-Type"); // ✅ NUEVO: Para rate limiting
                configuration.addExposedHeader("X-RateLimit-Remaining"); // ✅ NUEVO: Para rate limiting
                configuration.addExposedHeader("X-RateLimit-IP-Remaining"); // ✅ NUEVO: Para rate limiting
                configuration.addExposedHeader("X-RateLimit-User-Remaining"); // ✅ NUEVO: Para rate limiting

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

        @Bean
        public BCryptPasswordEncoder bCryptPasswordEncoder() {
                log.debug("🔐 Creando bean BCryptPasswordEncoder con strength 12");
                return new BCryptPasswordEncoder(12); // Strength 12 para mayor seguridad
        }

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