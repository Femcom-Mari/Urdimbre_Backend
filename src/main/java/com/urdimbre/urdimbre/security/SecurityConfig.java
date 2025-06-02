package com.urdimbre.urdimbre.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

        private final UserDetailsServiceImpl userDetailsService;
        private final RefreshTokenService refreshTokenService;

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                log.info("🔒 Configurando Security Filter Chain - VERSIÓN FINAL SEGURA");

                http
                                .csrf(csrf -> csrf.disable())
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                                .authorizeHttpRequests(auth -> auth

                                                .requestMatchers(
                                                                "/api/auth/login",
                                                                "/api/auth/register",
                                                                "/api/auth/refresh",
                                                                "/actuator/health",
                                                                "/error")
                                                .permitAll()

                                                .requestMatchers("/api/auth/logout").authenticated()
                                                .requestMatchers("/api/users/**").authenticated()
                                                .requestMatchers("/api/roles/**").hasRole("ADMIN")

                                                .anyRequest().authenticated())

                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                .addFilterBefore(
                                                new JwtAuthorizationFilter(userDetailsService, refreshTokenService),
                                                UsernamePasswordAuthenticationFilter.class);

                log.info("✅ Security Filter Chain SEGURO configurado");
                return http.build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                log.info("🌐 Configurando CORS");

                CorsConfiguration configuration = new CorsConfiguration();

                // Orígenes permitidos (ajusta según tu frontend)
                configuration.addAllowedOriginPattern("http://localhost:*");
                configuration.addAllowedOriginPattern("http://127.0.0.1:*");
                configuration.addAllowedOriginPattern("https://tu-dominio.com");

                // Métodos HTTP permitidos
                configuration.addAllowedMethod("GET");
                configuration.addAllowedMethod("POST");
                configuration.addAllowedMethod("PUT");
                configuration.addAllowedMethod("DELETE");
                configuration.addAllowedMethod("OPTIONS");

                // Headers permitidos
                configuration.addAllowedHeader("*");

                // Headers expuestos
                configuration.addExposedHeader("Authorization");
                configuration.addExposedHeader("Refresh-Token");

                // Permitir credentials
                configuration.setAllowCredentials(true);

                // Tiempo de cache para preflight
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

                // Solo permitir lo mínimo necesario
                firewall.setAllowUrlEncodedCarriageReturn(true);
                firewall.setAllowUrlEncodedPercent(true);
                firewall.setAllowUrlEncodedSlash(false); // Más seguro
                firewall.setAllowUrlEncodedPeriod(false); // Más seguro

                log.info("✅ HTTP Firewall configurado");
                return firewall;
        }

        @Bean
        public WebSecurityCustomizer webSecurityCustomizer() {
                return (web) -> web.httpFirewall(httpFirewall());
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }
}
