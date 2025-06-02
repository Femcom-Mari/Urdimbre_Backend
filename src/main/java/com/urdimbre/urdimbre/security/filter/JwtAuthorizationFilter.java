package com.urdimbre.urdimbre.security.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.urdimbre.urdimbre.security.constants.SecurityConstants;
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

    // Rutas que NO requieren autenticación
    private static final List<String> PUBLIC_PATHS = Arrays.asList(
            "/api/auth/register",
            "/api/auth/login",
            "/api/auth/refresh",
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

                String username = refreshTokenService.getUsernameFromToken(token);

                if (username != null) {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    if (refreshTokenService.validateToken(token)) {

                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());

                        authentication.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request));

                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        log.debug("User authenticated successfully: {}", username);
                    } else {
                        log.warn("Invalid JWT token for user: {}", username);
                    }
                } else {
                    log.warn("Could not extract username from token");
                }
            } catch (Exception e) {
                log.error("Error validating JWT token: {}", e.getMessage());
            }
        } else if (token == null) {
            log.debug("No JWT token found for protected path: {}", path);
        }

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(SecurityConstants.HEADER_STRING);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            return bearerToken.substring(SecurityConstants.TOKEN_PREFIX.length());
        }

        return null;
    }
}