package com.urdimbre.urdimbre.security;

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

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http.cors(cors -> cors.configurationSource(corsConfigurationSource()));

                http
                                .csrf(csrf -> csrf.disable())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authorizeHttpRequests(auth -> auth
                                                // Public endpoints
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

                                                // Professional endpoints - read access for users and admins
                                                .requestMatchers(HttpMethod.GET, "/api/professionals",
                                                                PROFESSIONALS_API_PATTERN)
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

                                                // Admin endpoints
                                                .requestMatchers("/api/admin/**").hasRole(ROLE_ADMIN)
                                                .requestMatchers("/api/roles/**").hasRole(ROLE_ADMIN)

                                                // Authenticated endpoints
                                                .requestMatchers(HttpMethod.POST, "/api/auth/logout").authenticated()
                                                .requestMatchers("/api/users/**").authenticated()

                                                // All other requests require authentication
                                                .anyRequest().authenticated())

                                .addFilterBefore(
                                                new JwtAuthorizationFilter(userDetailsService, refreshTokenService),
                                                UsernamePasswordAuthenticationFilter.class);

                return http.build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();

                // Allowed origins
                configuration.addAllowedOriginPattern("http://localhost:*");
                configuration.addAllowedOriginPattern("http://127.0.0.1:*");
                configuration.addAllowedOriginPattern("https://tu-dominio.com");
                configuration.addAllowedOriginPattern("https://*.tu-dominio.com");

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

                // Additional configurations
                configuration.setAllowCredentials(true);
                configuration.setMaxAge(3600L);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);

                return source;
        }

        @Bean
        public HttpFirewall httpFirewall() {
                StrictHttpFirewall firewall = new StrictHttpFirewall();

                // Security configurations
                firewall.setAllowUrlEncodedCarriageReturn(false);
                firewall.setAllowUrlEncodedPercent(true);
                firewall.setAllowUrlEncodedSlash(false);
                firewall.setAllowUrlEncodedPeriod(false);
                firewall.setAllowBackSlash(false);
                firewall.setAllowUrlEncodedLineFeed(false);
                firewall.setAllowSemicolon(false);
                firewall.setAllowUrlEncodedDoubleSlash(false);

                return firewall;
        }

        @Bean
        public WebSecurityCustomizer webSecurityCustomizer() {
                return (web) -> web.httpFirewall(httpFirewall());
        }

        @Bean
        public BCryptPasswordEncoder bCryptPasswordEncoder() {
                return new BCryptPasswordEncoder(12);
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder(12);
        }
}