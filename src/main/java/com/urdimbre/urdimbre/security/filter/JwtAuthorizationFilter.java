package com.urdimbre.urdimbre.security.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.urdimbre.urdimbre.service.token.RefreshTokenService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;
    private final RefreshTokenService refreshTokenService;

    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String HEADER_STRING = "Authorization";

    private static final List<String> PUBLIC_PATHS = Arrays.asList(
            "/api/auth/register",
            "/api/auth/login",
            "/api/auth/refresh",
            "/api/auth/invite-codes/validate",
            "/api/auth/invite-codes/info",
            "/api/auth/check-username",
            "/api/auth/check-email",
            "/api/auth/forgot-password",
            "/v3/api-docs",
            "/swagger-ui",
            "/swagger-resources",
            "/webjars",
            "/h2-console",
            "/actuator/health",
            "/error");

    @Override
    protected void doFilterInternal(
            @org.springframework.lang.NonNull HttpServletRequest request,
            @org.springframework.lang.NonNull HttpServletResponse response,
            @org.springframework.lang.NonNull FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();

        log.debug("🔍 Processing request: {} {}", method, path);

        // ✅ DEBUGGING MEJORADO - LOG DEL HEADER
        String authHeader = request.getHeader(HEADER_STRING);
        log.info("🔍 Auth Header for {}: {}", path,
                authHeader != null ? "Present (" + authHeader.length() + " chars)" : "Missing");

        if ("OPTIONS".equals(method)) {
            log.debug("✅ Allowing OPTIONS request for CORS");
            response.setStatus(HttpServletResponse.SC_OK);
            filterChain.doFilter(request, response);
            return;
        }

        boolean isPublicPath = PUBLIC_PATHS.stream()
                .anyMatch(path::startsWith);

        if (isPublicPath) {
            log.debug("🌐 Public path detected: {}", path);
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("🔒 Protected path, validating JWT: {}", path);

        String token = extractTokenFromRequest(request);

        if (token != null && !token.trim().isEmpty()) {
            log.info("🎯 Token extracted successfully, length: {}", token.length());

            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                try {
                    processJwtToken(token, request);
                } catch (Exception e) {
                    log.error("❌ Error validating JWT token: {}", e.getMessage(), e);
                }
            } else {
                log.debug("✅ Authentication already set in SecurityContext");
            }
        } else {
            log.warn("🚫 No valid JWT token found for protected path: {}", path);
        }

        filterChain.doFilter(request, response);
    }

    private void processJwtToken(String token, HttpServletRequest request) {
        try {
            log.debug("🔍 Processing JWT token...");

            // ✅ VALIDACIÓN PREVIA DEL TOKEN
            if (token.split("\\.").length != 3) {
                log.error("❌ Invalid JWT format - token parts: {}", token.split("\\.").length);
                return;
            }

            DecodedJWT decodedJWT = decodeJwtToken(token);

            if (decodedJWT == null) {
                log.warn("❌ Could not decode JWT token");
                return;
            }

            String username = decodedJWT.getSubject();

            if (username == null || username.trim().isEmpty()) {
                log.warn("❌ Could not extract username from token");
                return;
            }

            log.info("👤 Username extracted from token: {}", username);

            // ✅ VALIDACIÓN DEL TOKEN CON EL SERVICIO
            try {
                if (!refreshTokenService.validateAccessToken(token)) {
                    log.warn("❌ Invalid JWT access token for user: {}", username);
                    return;
                }
                log.debug("✅ Token validation successful");
            } catch (Exception e) {
                log.error("❌ Error validating token with RefreshTokenService: {}", e.getMessage());
                return;
            }

            Collection<GrantedAuthority> authorities = extractAuthoritiesFromToken(decodedJWT);

            if (authorities.isEmpty()) {
                log.debug("🔄 No authorities in token, loading from UserDetailsService for user: {}", username);
                try {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    authorities = userDetails.getAuthorities().stream()
                            .collect(Collectors.toList());
                    log.debug("✅ Authorities loaded from UserDetailsService: {}", authorities);
                } catch (Exception e) {
                    log.error("❌ Error loading user details for {}: {}", username, e.getMessage());
                    return;
                }
            }

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    username, // Principal: solo el username
                    null, // Credentials: null para JWT
                    authorities); // Authorities extraídas del token

            authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.info("✅ User authenticated successfully: {} with authorities: {}", username, authorities);

        } catch (Exception e) {
            log.error("❌ Error processing JWT token: {}", e.getMessage(), e);
        }
    }

    private DecodedJWT decodeJwtToken(String token) {
        try {
            log.debug("🔓 Decoding JWT token...");
            DecodedJWT decoded = JWT.decode(token); // Decodificación básica sin verificación
            log.debug("✅ JWT decoded successfully");
            return decoded;
        } catch (Exception e) {
            log.error("❌ Error decoding JWT token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 🔑 Extraer authorities del token JWT
     */
    private Collection<GrantedAuthority> extractAuthoritiesFromToken(DecodedJWT decodedJWT) {
        try {
            // ✅ EXTRAER CLAIM 'authorities' DEL TOKEN
            List<String> authoritiesList = decodedJWT.getClaim("authorities").asList(String.class);

            if (authoritiesList != null && !authoritiesList.isEmpty()) {
                Collection<GrantedAuthority> authorities = authoritiesList.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                log.info("🎭 Extracted authorities from token: {}", authoritiesList);
                return authorities;
            } else {
                log.debug("🎭 No authorities claim found in token");
            }

        } catch (Exception e) {
            log.warn("⚠️ Error extracting authorities from token: {}", e.getMessage());
        }

        return List.of(); // Retornar lista vacía si no se pueden extraer
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(HEADER_STRING);

        log.debug("🔍 Raw Authorization header: {}", bearerToken);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) {
            String token = bearerToken.substring(TOKEN_PREFIX.length());
            log.debug("✅ Token extracted from Bearer header, length: {}", token.length());
            return token;
        }

        log.debug("❌ No valid Bearer token found in header");
        return null;
    }
}