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

        @Value("${spring.profiles.active:dev}")
        private String activeProfile;

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                log.info("🔒 Configurando Security Filter Chain SEGURO - Perfil: {}", activeProfile);

                http
                                .csrf(csrf -> csrf.disable())
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                                // ================================
                                // HEADERS DE SEGURIDAD MÁXIMA
                                // ================================
                                .headers(headers -> headers
                                                // Anti-Clickjacking (nueva sintaxis)
                                                .frameOptions(frameOptions -> frameOptions.deny())

                                                // Content Type Protection (nueva sintaxis)
                                                .contentTypeOptions(contentTypeOptions -> {
                                                })

                                                // HSTS Protection (solo HTTPS en producción)
                                                .httpStrictTransportSecurity(hstsConfig -> {
                                                        if (isProductionEnvironment()) {
                                                                hstsConfig
                                                                                .maxAgeInSeconds(31536000) // 1 año
                                                                                .includeSubDomains(true)
                                                                                .preload(true);
                                                        }
                                                })

                                                // Content Security Policy
                                                .contentSecurityPolicy(cspConfig -> cspConfig
                                                                .policyDirectives(buildContentSecurityPolicy()))

                                                // Headers de seguridad adicionales
                                                .addHeaderWriter((request, response) -> {
                                                        // XSS Protection
                                                        response.setHeader("X-XSS-Protection", "1; mode=block");
                                                        // Referrer Policy
                                                        response.setHeader("Referrer-Policy",
                                                                        "strict-origin-when-cross-origin");
                                                        // Permissions Policy
                                                        response.setHeader("Permissions-Policy",
                                                                        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
                                                                                        +
                                                                                        "magnetometer=(), gyroscope=(), clipboard-read=(), clipboard-write=()");
                                                        // Cache Control para endpoints sensibles
                                                        if (request.getRequestURI().startsWith("/api/auth") ||
                                                                        request.getRequestURI()
                                                                                        .startsWith("/api/admin")) {
                                                                response.setHeader("Cache-Control",
                                                                                "no-store, no-cache, must-revalidate, max-age=0");
                                                                response.setHeader("Pragma", "no-cache");
                                                                response.setHeader("Expires", "0");
                                                        }
                                                }))

                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                // ================================
                                // AUTORIZACIÓN SEGURA
                                // ================================
                                .authorizeHttpRequests(auth -> auth
                                                // ================================
                                                // ENDPOINTS PÚBLICOS (mínimos necesarios)
                                                // ================================
                                                .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/api/auth/register").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/api/auth/refresh").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/api/auth/forgot-password")
                                                .permitAll()

                                                // Endpoints de validación (solo GET)
                                                .requestMatchers(HttpMethod.GET, "/api/auth/check-username").permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/auth/check-email").permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/auth/invite-codes/validate")
                                                .permitAll()
                                                .requestMatchers(HttpMethod.GET, "/api/auth/invite-codes/info")
                                                .permitAll()

                                                // Health checks
                                                .requestMatchers("/actuator/health").permitAll()
                                                .requestMatchers("/error").permitAll()

                                                // ================================
                                                // 🔧 ENDPOINTS DE DESARROLLO (SOLO EN DEV)
                                                // ================================
                                                .requestMatchers("/api/dev/**")
                                                .access((authentication, context) -> isDevelopmentEnvironment())
                                                .requestMatchers("/actuator/**")
                                                .access((authentication, context) -> isDevelopmentEnvironment())
                                                .requestMatchers("/api/test/**")
                                                .access((authentication, context) -> isDevelopmentEnvironment())

                                                // ================================
                                                // ✅ ENDPOINTS DE ADMIN (máxima seguridad)
                                                // ================================
                                                .requestMatchers("/api/admin/**").hasRole(ROLE_ADMIN)
                                                .requestMatchers("/api/roles/**").hasRole(ROLE_ADMIN)
                                                .requestMatchers("/api/auth/rate-limit-stats").hasRole(ROLE_ADMIN)
                                                .requestMatchers("/api/invite-codes/**").hasRole(ROLE_ADMIN) // Gestión
                                                                                                             // de
                                                                                                             // códigos

                                                // Endpoints administrativos específicos
                                                .requestMatchers(HttpMethod.DELETE, "/api/**").hasRole(ROLE_ADMIN)
                                                .requestMatchers("/api/users/admin/**").hasRole(ROLE_ADMIN)

                                                // ================================
                                                // PROFESSIONALS ENDPOINTS (control granular)
                                                // ================================
                                                .requestMatchers(HttpMethod.GET, "/api/professionals")
                                                .hasAnyRole(ROLE_USER, ROLE_ADMIN)
                                                .requestMatchers(HttpMethod.GET, PROFESSIONALS_API_PATTERN)
                                                .hasAnyRole(ROLE_USER, ROLE_ADMIN)

                                                // Solo admins pueden modificar
                                                .requestMatchers(HttpMethod.POST, "/api/professionals")
                                                .hasRole(ROLE_ADMIN)
                                                .requestMatchers(HttpMethod.PUT, PROFESSIONALS_API_PATTERN)
                                                .hasRole(ROLE_ADMIN)
                                                .requestMatchers(HttpMethod.PATCH, PROFESSIONALS_API_PATTERN)
                                                .hasRole(ROLE_ADMIN)
                                                .requestMatchers(HttpMethod.DELETE, PROFESSIONALS_API_PATTERN)
                                                .hasRole(ROLE_ADMIN)

                                                // ================================
                                                // ENDPOINTS AUTENTICADOS
                                                // ================================
                                                .requestMatchers(HttpMethod.POST, "/api/auth/logout").authenticated()
                                                .requestMatchers(HttpMethod.GET, "/api/users/me").authenticated()
                                                .requestMatchers(HttpMethod.PUT, "/api/users/me").authenticated()
                                                .requestMatchers(HttpMethod.GET, "/api/users/profile/**")
                                                .authenticated()

                                                // ================================
                                                // ✅ RESTO DE ENDPOINTS AUTENTICADOS
                                                // ================================
                                                .anyRequest().authenticated())

                                .addFilterBefore(
                                                new JwtAuthorizationFilter(userDetailsService, refreshTokenService),
                                                UsernamePasswordAuthenticationFilter.class);

                log.info("✅ Security Filter Chain configurado con máxima seguridad para: {}", activeProfile);
                return http.build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                log.info("🌐 Configurando CORS seguro para: {}", activeProfile);

                CorsConfiguration configuration = new CorsConfiguration();

                // ================================
                // ORÍGENES SEGUROS POR ENTORNO
                // ================================
                if (isProductionEnvironment()) {
                        // 🚀 PRODUCCIÓN: Solo dominios específicos con HTTPS
                        configuration.addAllowedOriginPattern("https://urdimbre.com");
                        configuration.addAllowedOriginPattern("https://*.urdimbre.com");
                        configuration.addAllowedOriginPattern("https://app.urdimbre.com");
                        log.info("🔒 CORS configurado para PRODUCCIÓN - solo HTTPS");
                } else {
                        // 🔧 DESARROLLO: Localhost limitado
                        configuration.addAllowedOriginPattern("http://localhost:3000");
                        configuration.addAllowedOriginPattern("http://localhost:3001");
                        configuration.addAllowedOriginPattern("http://localhost:5173"); // Vite
                        configuration.addAllowedOriginPattern("http://127.0.0.1:3000");
                        log.info("🔧 CORS configurado para DESARROLLO - puertos específicos");
                }

                // Métodos HTTP permitidos
                configuration.addAllowedMethod("GET");
                configuration.addAllowedMethod("POST");
                configuration.addAllowedMethod("PUT");
                configuration.addAllowedMethod("PATCH");
                configuration.addAllowedMethod("DELETE");
                configuration.addAllowedMethod("OPTIONS");

                // Headers permitidos
                configuration.addAllowedHeader("Authorization");
                configuration.addAllowedHeader("Content-Type");
                configuration.addAllowedHeader("Accept");
                configuration.addAllowedHeader("Origin");
                configuration.addAllowedHeader("X-Requested-With");
                configuration.addAllowedHeader("Refresh-Token");

                // Headers expuestos (para el frontend)
                configuration.addExposedHeader("Authorization");
                configuration.addExposedHeader("Refresh-Token");
                configuration.addExposedHeader("X-RateLimit-Remaining");
                configuration.addExposedHeader("X-RateLimit-IP-Remaining");
                configuration.addExposedHeader("X-RateLimit-User-Remaining");
                configuration.addExposedHeader("Retry-After");

                // Configuraciones adicionales seguras
                configuration.setAllowCredentials(true);
                configuration.setMaxAge(isProductionEnvironment() ? 1800L : 3600L); // Menor en prod

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);

                return source;
        }

        @Bean
        public HttpFirewall httpFirewall() {
                log.info("🛡️ Configurando HTTP Firewall ULTRA SEGURO");

                StrictHttpFirewall firewall = new StrictHttpFirewall();

                // ================================
                // CONFIGURACIÓN SUPER ESTRICTA
                // ================================
                firewall.setAllowUrlEncodedCarriageReturn(false);
                firewall.setAllowUrlEncodedPercent(false); // Más restrictivo
                firewall.setAllowUrlEncodedSlash(false);
                firewall.setAllowUrlEncodedPeriod(false);
                firewall.setAllowBackSlash(false);
                firewall.setAllowUrlEncodedLineFeed(false);
                firewall.setAllowSemicolon(false);
                firewall.setAllowUrlEncodedDoubleSlash(false);
                firewall.setAllowNull(false);

                // Bloquear caracteres peligrosos (métodos existentes)
                firewall.setAllowNull(false);

                log.info(" HTTP Firewall configurado con protección MÁXIMA");
                return firewall;
        }

        @Bean
        public WebSecurityCustomizer webSecurityCustomizer() {
                return web -> web.httpFirewall(httpFirewall());
        }

        @Bean
        public BCryptPasswordEncoder bCryptPasswordEncoder() {
                int strength = isProductionEnvironment() ? 14 : 12; // Más fuerte en producción
                log.debug("🔐 BCryptPasswordEncoder con strength: {}", strength);
                return new BCryptPasswordEncoder(strength);
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                int strength = isProductionEnvironment() ? 14 : 12;
                log.debug("🔐 PasswordEncoder con strength: {}", strength);
                return new BCryptPasswordEncoder(strength);
        }

        // ================================
        // MÉTODOS DE SEGURIDAD
        // ================================

        private boolean isProductionEnvironment() {
                return "prod".equals(activeProfile) ||
                                "production".equals(activeProfile) ||
                                "prd".equals(activeProfile);
        }

        private org.springframework.security.authorization.AuthorizationDecision isDevelopmentEnvironment() {
                boolean isDev = "dev".equals(activeProfile) ||
                                "development".equals(activeProfile) ||
                                "local".equals(activeProfile);

                if (!isDev) {
                        log.warn("🚫 Acceso denegado a endpoint de desarrollo en: {}", activeProfile);
                }

                return new org.springframework.security.authorization.AuthorizationDecision(isDev);
        }

        private String buildContentSecurityPolicy() {
                if (isProductionEnvironment()) {
                        // CSP ULTRA ESTRICTO PARA PRODUCCIÓN
                        return "default-src 'none'; " +
                                        "script-src 'self'; " +
                                        "style-src 'self' 'unsafe-inline'; " +
                                        "img-src 'self' data: https:; " +
                                        "font-src 'self'; " +
                                        "connect-src 'self' https:; " +
                                        "frame-ancestors 'none'; " +
                                        "form-action 'self'; " +
                                        "base-uri 'self'; " +
                                        "object-src 'none'; " +
                                        "media-src 'none'; " +
                                        "worker-src 'none'; " +
                                        "manifest-src 'self'; " +
                                        "upgrade-insecure-requests; " +
                                        "block-all-mixed-content";
                } else {
                        // CSP PERMISIVO PARA DESARROLLO
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