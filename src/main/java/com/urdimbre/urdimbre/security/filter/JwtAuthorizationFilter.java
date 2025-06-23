package com.urdimbre.urdimbre.security.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

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
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.urdimbre.urdimbre.service.token.RefreshTokenService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;
    private final RefreshTokenService refreshTokenService;
    private final String jwtSecret;
    private final String jwtIssuer;

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

    public JwtAuthorizationFilter(UserDetailsService userDetailsService,
            RefreshTokenService refreshTokenService,
            String jwtSecret,
            String jwtIssuer) {
        this.userDetailsService = userDetailsService;
        this.refreshTokenService = refreshTokenService;
        this.jwtSecret = jwtSecret;
        this.jwtIssuer = jwtIssuer != null ? jwtIssuer : "urdimbre";
    }

    @Override
    protected void doFilterInternal(
            @org.springframework.lang.NonNull HttpServletRequest request,
            @org.springframework.lang.NonNull HttpServletResponse response,
            @org.springframework.lang.NonNull FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();

        if ("OPTIONS".equals(method)) {
            response.setStatus(HttpServletResponse.SC_OK);
            filterChain.doFilter(request, response);
            return;
        }

        boolean isPublicPath = PUBLIC_PATHS.stream()
                .anyMatch(path::startsWith);

        if (isPublicPath) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = extractTokenFromRequest(request);

        if (token == null || token.trim().isEmpty()) {
            log.warn("Token JWT no encontrado para ruta protegida: {}", path);
            sendUnauthorizedResponse(response, "Token de acceso requerido");
            return;
        }

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                if (processJwtToken(token, request)) {
                    log.trace("Autenticación JWT exitosa");
                } else {
                    sendUnauthorizedResponse(response, "Token inválido");
                    return;
                }
            } catch (Exception e) {
                log.error("Error validando token JWT: {}", e.getMessage());
                sendUnauthorizedResponse(response, "Error de validación del token");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean processJwtToken(String token, HttpServletRequest request) {
        try {
            if (token.split("\\.").length != 3) {
                log.warn("Formato JWT inválido");
                return false;
            }

            DecodedJWT decodedJWT = verifyJwtToken(token);
            if (decodedJWT == null) {
                log.warn("Verificación JWT falló");
                return false;
            }

            String username = decodedJWT.getSubject();
            if (username == null || username.trim().isEmpty()) {
                log.warn("No hay nombre de usuario en el token JWT");
                return false;
            }

            if (!refreshTokenService.validateAccessToken(token)) {
                log.warn("Validación de token falló para usuario: {}", username);
                return false;
            }

            Collection<GrantedAuthority> authorities = extractAuthoritiesFromToken(decodedJWT);

            if (authorities.isEmpty()) {
                authorities = loadUserAuthorities(username);
                if (authorities == null) {
                    return false;
                }
            }

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null,
                    authorities);

            authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            return true;

        } catch (JWTVerificationException e) {
            log.warn("Verificación JWT falló: {}", e.getMessage());
            return false;
        } catch (RuntimeException e) {
            log.error("Excepción en tiempo de ejecución procesando token JWT: {}", e.getMessage());
            return false;
        }
    }

    private DecodedJWT verifyJwtToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC512(jwtSecret);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(jwtIssuer)
                    .build();

            return verifier.verify(token);

        } catch (JWTVerificationException e) {
            log.warn("Verificación JWT falló: {}", e.getMessage());
            return null;
        } catch (IllegalArgumentException e) {
            log.error("Configuración de algoritmo JWT inválida: {}", e.getMessage());
            return null;
        }
    }

    private Collection<GrantedAuthority> loadUserAuthorities(String username) {
        try {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            return userDetails.getAuthorities().stream().map(a -> (GrantedAuthority) a).toList();
        } catch (RuntimeException e) {
            log.error("Error cargando detalles del usuario para {}: {}", username, e.getMessage());
            return List.of();
        }
    }

    private Collection<GrantedAuthority> extractAuthoritiesFromToken(DecodedJWT decodedJWT) {
        try {
            List<String> authoritiesList = decodedJWT.getClaim("authorities").asList(String.class);

            if (authoritiesList != null && !authoritiesList.isEmpty()) {
                return authoritiesList.stream()
                        .map(SimpleGrantedAuthority::new)
                        .map(a -> (GrantedAuthority) a)
                        .toList();
            }
        } catch (RuntimeException e) {
            log.trace("No hay claim de authorities en el token: {}", e.getMessage());
        }

        return List.of();
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(HEADER_STRING);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) {
            return bearerToken.substring(TOKEN_PREFIX.length());
        }

        return null;
    }

    private void sendUnauthorizedResponse(HttpServletResponse response, String message)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write(
                String.format("{\"error\":\"No autorizado\",\"message\":\"%s\"}", message));
    }
}