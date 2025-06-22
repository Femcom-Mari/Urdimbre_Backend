package com.urdimbre.urdimbre.service.token;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.issuer:urdimbre-preproduction}")
    private String jwtIssuer;

    @Value("${jwt.access-token-expiration:900000}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration:86400000}")
    private long refreshTokenExpiration;

    private final BlacklistedTokenService blacklistedTokenService;
    private final UserDetailsService userDetailsService;

    private final Map<String, String> refreshTokenStore = new ConcurrentHashMap<>();

    private Algorithm algorithm;
    private JWTVerifier verifier;

    @PostConstruct
    public void init() {
        logger.info("🔐 Inicializando RefreshTokenService con Blacklist...");

        if (jwtSecret == null || jwtSecret.trim().isEmpty()) {
            throw new IllegalStateException("❌ JWT secret no está configurado");
        }

        if (jwtSecret.length() < 64) {
            throw new IllegalStateException("❌ JWT secret debe tener al menos 64 caracteres");
        }

        this.algorithm = Algorithm.HMAC512(jwtSecret);
        this.verifier = JWT.require(algorithm)
                .withIssuer(jwtIssuer)
                .build();

        logger.info("✅ RefreshTokenService inicializado con algoritmo HS512 y Blacklist");
        logger.info("🔐 JWT Secret length: {} caracteres", jwtSecret.length());
        logger.info("🏷️ JWT Issuer: {}", jwtIssuer);
        logger.info("⏰ Access Token Expiration: {} ms", accessTokenExpiration);
        logger.info("⏰ Refresh Token Expiration: {} ms", refreshTokenExpiration);
    }

    public void saveToken(String refreshToken, String username) {
        refreshTokenStore.put(refreshToken, username);
        logger.debug("🔐 Refresh token guardado para usuario: {}", username);
    }

    public String getUsernameFromToken(String refreshToken) {
        try {
            if (blacklistedTokenService.isFullTokenBlacklisted(refreshToken)) {
                logger.warn("🚫 Intento de usar refresh token en blacklist");
                return null;
            }

            DecodedJWT decodedJWT = verifier.verify(refreshToken);
            String username = decodedJWT.getSubject();

            if (!refreshTokenStore.containsKey(refreshToken)) {
                logger.warn("⚠️ Refresh token no encontrado en almacén para usuario: {}", username);
                return null;
            }

            logger.debug("✅ Username extraído del refresh token: {}", username);
            return username;

        } catch (JWTVerificationException e) {
            logger.warn("❌ Error verificando refresh token: {}", e.getMessage());
            return null;
        }
    }

    public void removeToken(String refreshToken) {
        String username = refreshTokenStore.remove(refreshToken);
        if (username != null) {
            blacklistedTokenService.blacklistToken(refreshToken, "Token usado para refresh");
            logger.info("🗑️ Refresh token removido y agregado a blacklist para usuario: {}", username);
        }
    }

    public boolean validateToken(String refreshToken) {
        try {
            if (blacklistedTokenService.isFullTokenBlacklisted(refreshToken)) {
                logger.warn("🚫 Refresh token está en blacklist");
                return false;
            }

            DecodedJWT decodedJWT = verifier.verify(refreshToken);

            Date expirationDate = decodedJWT.getExpiresAt();
            if (expirationDate != null && expirationDate.before(new Date())) {
                logger.warn("⚠️ Refresh token expirado");
                removeToken(refreshToken);
                return false;
            }

            boolean existsInStore = refreshTokenStore.containsKey(refreshToken);
            if (!existsInStore) {
                logger.warn("⚠️ Refresh token no encontrado en almacén");
                return false;
            }

            logger.debug("✅ Refresh token válido");
            return true;

        } catch (JWTVerificationException e) {
            logger.warn("❌ Refresh token inválido: {}", e.getMessage());
            removeToken(refreshToken);
            return false;
        }
    }

    public boolean validateAccessToken(String accessToken) {
        try {
            if (blacklistedTokenService.isFullTokenBlacklisted(accessToken)) {
                logger.warn("🚫 Access token está en blacklist");
                return false;
            }

            DecodedJWT decodedJWT = verifier.verify(accessToken);

            String tokenType = decodedJWT.getClaim("type").asString();
            if (!"access".equals(tokenType)) {
                logger.warn("⚠️ Token no es de tipo access: {}", tokenType);
                return false;
            }

            Date expirationDate = decodedJWT.getExpiresAt();
            if (expirationDate != null && expirationDate.before(new Date())) {
                logger.warn("⚠️ Access token expirado");
                return false;
            }

            logger.debug("✅ Access token válido");
            return true;

        } catch (JWTVerificationException e) {
            logger.warn("❌ Access token inválido: {}", e.getMessage());
            return false;
        }
    }

    public String generateRefreshToken(String username) {
        try {
            String tokenId = UUID.randomUUID().toString();

            String refreshToken = JWT.create()
                    .withSubject(username)
                    .withIssuer(jwtIssuer)
                    .withClaim("tokenId", tokenId)
                    .withClaim("type", "refresh")
                    .withIssuedAt(new Date())
                    .withExpiresAt(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                    .sign(algorithm);

            saveToken(refreshToken, username);

            logger.debug("🔄 Refresh token generado para usuario: {}", username);
            return refreshToken;

        } catch (Exception e) {
            logger.error("❌ Error generando refresh token para usuario {}: {}", username, e.getMessage());
            throw new RuntimeException("Error generando refresh token", e);
        }
    }

    public String generateAccessToken(String username) {
        try {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            List<String> authorities = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            String accessToken = JWT.create()
                    .withSubject(username)
                    .withIssuer(jwtIssuer) // ✅ CORREGIDO: Añadido issuer
                    .withClaim("type", "access")
                    .withClaim("authorities", authorities)
                    .withIssuedAt(new Date())
                    .withExpiresAt(new Date(System.currentTimeMillis() + accessTokenExpiration))
                    .sign(algorithm);

            logger.debug("🎫 Access token generado para usuario: {} con authorities: {}", username, authorities);
            return accessToken;

        } catch (Exception e) {
            logger.error("❌ Error generando access token para usuario {}: {}", username, e.getMessage());
            throw new RuntimeException("Error generando access token", e);
        }
    }

    public String extractRefreshTokenFromRequest(HttpServletRequest request) {
        String refreshToken = request.getHeader("Refresh-Token");

        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            refreshToken = request.getParameter("refreshToken");
        }

        return refreshToken;
    }

    public void cleanupExpiredTokens() {
        int initialSize = refreshTokenStore.size();

        refreshTokenStore.entrySet().removeIf(entry -> {
            String token = entry.getKey();
            try {
                DecodedJWT decodedJWT = verifier.verify(token);
                Date expirationDate = decodedJWT.getExpiresAt();
                if (expirationDate != null && expirationDate.before(new Date())) {
                    blacklistedTokenService.blacklistToken(token, "Expirado durante limpieza");
                    return true;
                }
                return false;
            } catch (JWTVerificationException e) {
                blacklistedTokenService.blacklistToken(token, "Inválido durante limpieza");
                return true;
            }
        });

        int removedTokens = initialSize - refreshTokenStore.size();
        if (removedTokens > 0) {
            logger.info("🧹 Limpieza completada: {} tokens expirados removidos y agregados a blacklist", removedTokens);
        }
    }

    public void invalidateToken(String refreshToken, String reason) {
        String username = refreshTokenStore.remove(refreshToken);
        if (username != null) {
            blacklistedTokenService.blacklistToken(refreshToken, reason);
            logger.info("🚫 Token invalidado para usuario: {} (razón: {})", username, reason);
        }
    }

    public Map<String, Object> getStats() {
        BlacklistedTokenService.BlacklistStats blacklistStats = blacklistedTokenService.getStatistics();

        return Map.of(
                "activeRefreshTokens", refreshTokenStore.size(),
                "blacklistedTokens", blacklistStats.getTotalBlacklistedTokens(),
                "algorithmUsed", "HS512",
                "issuer", jwtIssuer,
                "accessTokenExpirationMs", accessTokenExpiration,
                "refreshTokenExpirationMs", refreshTokenExpiration);
    }
}