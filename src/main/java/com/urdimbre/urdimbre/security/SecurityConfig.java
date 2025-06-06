package com.urdimbre.urdimbre.security;

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

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                log.info("🔒 Configurando Security Filter Chain - VERSIÓN FINAL SEGURA CON CÓDIGOS DE INVITACIÓN");

                http
                                .csrf(csrf -> csrf.disable())
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

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
                                                .requestMatchers("/api/professionals/**").authenticated()

                                                // ================================
                                                // ✅ RESTO DE ENDPOINTS (requieren autenticación)
                                                // ================================
                                                .anyRequest().authenticated())

                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                .addFilterBefore(
                                                new JwtAuthorizationFilter(userDetailsService, refreshTokenService),
                                                UsernamePasswordAuthenticationFilter.class);

                log.info("✅ Security Filter Chain SEGURO configurado con códigos de invitación");
                return http.build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                log.info("🌐 Configurando CORS");

                CorsConfiguration configuration = new CorsConfiguration();

                // ================================
                // ✅ ORÍGENES PERMITIDOS
                // ================================
                // Desarrollo local
                configuration.addAllowedOriginPattern("http://localhost:*");
                configuration.addAllowedOriginPattern("http://127.0.0.1:*");

                // Producción (ajusta según tu dominio)
                configuration.addAllowedOriginPattern("https://tu-dominio.com");
                configuration.addAllowedOriginPattern("https://*.tu-dominio.com");

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

                // ================================
                // ✅ CONFIGURACIONES ADICIONALES
                // ================================
                // Permitir credentials (cookies, headers de autorización)
                configuration.setAllowCredentials(true);

                // Tiempo de cache para preflight requests (1 hora)
                configuration.setMaxAge(3600L);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);

                log.info("✅ CORS configurado correctamente");
                return source;
        }

        @Bean
        public HttpFirewall httpFirewall() {
                log.info("🛡️ Configurando HTTP Firewall");

                StrictHttpFirewall firewall = new StrictHttpFirewall();

                // ================================
                // ✅ CONFIGURACIONES DE SEGURIDAD
                // ================================
                // Permitir caracteres necesarios para códigos de invitación
                firewall.setAllowUrlEncodedCarriageReturn(false); // Más seguro
                firewall.setAllowUrlEncodedPercent(true); // Necesario para query params
                firewall.setAllowUrlEncodedSlash(false); // Más seguro
                firewall.setAllowUrlEncodedPeriod(false); // Más seguro
                firewall.setAllowBackSlash(false); // Más seguro
                firewall.setAllowUrlEncodedLineFeed(false); // Más seguro
                // firewall.setAllowUrlEncodedTab(false); // Más seguro (no disponible en
                // StrictHttpFirewall)

                // Permitir algunos caracteres comunes en URLs
                firewall.setAllowSemicolon(false); // Más seguro
                firewall.setAllowUrlEncodedDoubleSlash(false); // Más seguro

                log.info("✅ HTTP Firewall configurado con seguridad mejorada");
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
                log.debug("🔐 Creando bean BCryptPasswordEncoder");
                return new BCryptPasswordEncoder(12); // Strength 12 para mayor seguridad
        }

        /**
         * Bean PasswordEncoder para compatibilidad con Spring Security
         */
        @Bean
        public PasswordEncoder passwordEncoder() {
                log.debug("🔐 Creando bean PasswordEncoder");
                return new BCryptPasswordEncoder(12); // Strength 12 para mayor seguridad
        }
}