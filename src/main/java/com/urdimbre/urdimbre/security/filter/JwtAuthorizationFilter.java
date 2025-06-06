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

    // Constantes propias del filtro (sin depender de SecurityConstants)
    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String HEADER_STRING = "Authorization";

    // Rutas que NO requieren autenticación
    private static final List<String> PUBLIC_PATHS = Arrays.asList(
            "/api/auth/register",
            "/api/auth/login",
            "/api/auth/refresh",
            "/api/auth/invite-codes/validate",
            "/api/auth/invite-codes/info",
            "/v3/api-docs",
            "/swagger-ui",
            "/swagger-resources",
            "/webjars",
            "/h2-console",
            "/actuator/health");

    @Override
    protected void doFilterInternal(
            @org.springframework.lang.NonNull HttpServletRequest request,
            @org.springframework.lang.NonNull HttpServletResponse response,
            @org.springframework.lang.NonNull FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();

        log.debug("Processing request: {} {}", method, path);

        if ("OPTIONS".equals(method)) {
            log.debug("Allowing OPTIONS request for CORS");
            response.setStatus(HttpServletResponse.SC_OK);
            filterChain.doFilter(request, response);
            return;
        }

        boolean isPublicPath = PUBLIC_PATHS.stream()
                .anyMatch(path::startsWith);

        if (isPublicPath) {
            log.debug("Public path detected: {}", path);
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("Protected path, validating JWT: {}", path);

        String token = extractTokenFromRequest(request);

        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                // ✅ MÉTODO MEJORADO: Procesar token JWT completo
                processJwtToken(token, request);

            } catch (Exception e) {
                log.error("Error validating JWT token: {}", e.getMessage());
            }
        } else if (token == null) {
            log.debug("No JWT token found for protected path: {}", path);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * ✅ NUEVO MÉTODO: Procesar token JWT y extraer authorities
     */
    private void processJwtToken(String token, HttpServletRequest request) {
        try {
            // 🔍 DECODIFICAR JWT PARA EXTRAER CLAIMS
            DecodedJWT decodedJWT = decodeJwtToken(token);

            if (decodedJWT == null) {
                log.warn("Could not decode JWT token");
                return;
            }

            String username = decodedJWT.getSubject();

            if (username == null) {
                log.warn("Could not extract username from token");
                return;
            }

            // ✅ VALIDAR ACCESS TOKEN (NO REFRESH TOKEN)
            if (!refreshTokenService.validateAccessToken(token)) {
                log.warn("Invalid JWT access token for user: {}", username);
                return;
            }

            // ✅ EXTRAER AUTHORITIES DEL TOKEN JWT
            Collection<GrantedAuthority> authorities = extractAuthoritiesFromToken(decodedJWT);

            if (authorities.isEmpty()) {
                // ✅ FALLBACK: Cargar desde UserDetailsService si no hay authorities en el token
                log.debug("No authorities in token, loading from UserDetailsService for user: {}", username);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                authorities = userDetails.getAuthorities().stream()
                        .collect(Collectors.toList());
            }

            // ✅ CREAR AUTHENTICATION CON AUTHORITIES DEL TOKEN
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    username, // Principal: solo el username
                    null, // Credentials: null para JWT
                    authorities); // ✅ Authorities extraídas del token

            authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("User authenticated successfully: {} with authorities: {}", username, authorities);

        } catch (Exception e) {
            log.error("Error processing JWT token: {}", e.getMessage());
        }
    }

    /**
     * 🔍 NUEVO MÉTODO: Decodificar JWT token
     */
    private DecodedJWT decodeJwtToken(String token) {
        try {
            // ✅ USAR EL MISMO ALGORITMO QUE EL RefreshTokenService
            // Nota: Idealmente esto debería estar en un servicio compartido
            return JWT.decode(token); // Decodificación básica sin verificación

        } catch (Exception e) {
            log.warn("Error decoding JWT token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 🔑 NUEVO MÉTODO: Extraer authorities del token JWT
     */
    private Collection<GrantedAuthority> extractAuthoritiesFromToken(DecodedJWT decodedJWT) {
        try {
            // ✅ EXTRAER CLAIM 'authorities' DEL TOKEN
            List<String> authoritiesList = decodedJWT.getClaim("authorities").asList(String.class);

            if (authoritiesList != null && !authoritiesList.isEmpty()) {
                Collection<GrantedAuthority> authorities = authoritiesList.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                log.debug("Extracted authorities from token: {}", authoritiesList);
                return authorities;
            }

        } catch (Exception e) {
            log.warn("Error extracting authorities from token: {}", e.getMessage());
        }

        return List.of(); // Retornar lista vacía si no se pueden extraer
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(HEADER_STRING);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) {
            return bearerToken.substring(TOKEN_PREFIX.length());
        }

        return null;
    }
}