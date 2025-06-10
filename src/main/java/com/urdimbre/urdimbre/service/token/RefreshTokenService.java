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

    // 🔐 INYECCIÓN DIRECTA DE VARIABLES (no usar SecurityConstants estáticas)
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token-expiration:900000}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration:86400000}")
    private long refreshTokenExpiration;

    // 🔐 INYECTAR SERVICIOS NECESARIOS
    private final BlacklistedTokenService blacklistedTokenService;
    private final UserDetailsService userDetailsService; // ✅ NUEVO: Para cargar authorities

    // 🔐 ALMACENAMIENTO EN MEMORIA PARA REFRESH TOKENS
    private final Map<String, String> refreshTokenStore = new ConcurrentHashMap<>();

    // 🛡️ ALGORITMO DE FIRMA SEGURO
    private Algorithm algorithm;
    private JWTVerifier verifier;

    @PostConstruct
    public void init() {
        logger.info("🔐 Inicializando RefreshTokenService con Blacklist...");

        // ✅ VALIDAR JWT SECRET ANTES DE USAR
        if (jwtSecret == null || jwtSecret.trim().isEmpty()) {
            throw new IllegalStateException("❌ JWT secret no está configurado");
        }

        if (jwtSecret.length() < 64) {
            throw new IllegalStateException("❌ JWT secret debe tener al menos 64 caracteres");
        }

        // ✅ USAR ALGORITMO HS512 (MÁS SEGURO QUE HS256)
        this.algorithm = Algorithm.HMAC512(jwtSecret);
        this.verifier = JWT.require(algorithm).build();

        logger.info("✅ RefreshTokenService inicializado con algoritmo HS512 y Blacklist");
        logger.info("🔐 JWT Secret length: {} caracteres", jwtSecret.length());
        logger.info("⏰ Access Token Expiration: {} ms", accessTokenExpiration);
        logger.info("⏰ Refresh Token Expiration: {} ms", refreshTokenExpiration);
    }

    /**
     * 💾 Guardar refresh token en el almacén
     */
    public void saveToken(String refreshToken, String username) {
        refreshTokenStore.put(refreshToken, username);
        logger.debug("🔐 Refresh token guardado para usuario: {}", username);
    }

    /**
     * 👤 Obtener username desde refresh token CON VERIFICACIÓN DE BLACKLIST
     */
    public String getUsernameFromToken(String refreshToken) {
        try {
            // 🚫 VERIFICAR BLACKLIST PRIMERO
            if (blacklistedTokenService.isFullTokenBlacklisted(refreshToken)) {
                logger.warn("🚫 Intento de usar refresh token en blacklist");
                return null;
            }

            // ✅ VERIFICAR FIRMA Y OBTENER CLAIMS
            DecodedJWT decodedJWT = verifier.verify(refreshToken);
            String username = decodedJWT.getSubject();

            // ✅ VERIFICAR QUE EL TOKEN EXISTE EN NUESTRO ALMACÉN
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

    /**
     * 🗑️ Remover refresh token del almacén Y AGREGARLO A BLACKLIST
     */
    public void removeToken(String refreshToken) {
        String username = refreshTokenStore.remove(refreshToken);
        if (username != null) {
            // 🚫 AGREGAR A BLACKLIST AL REMOVER
            blacklistedTokenService.blacklistToken(refreshToken, "Token usado para refresh");
            logger.info("🗑️ Refresh token removido y agregado a blacklist para usuario: {}", username);
        }
    }

    /**
     * ✅ Validar refresh token CON VERIFICACIÓN DE BLACKLIST
     */
    public boolean validateToken(String refreshToken) {
        try {
            // 🚫 VERIFICAR BLACKLIST PRIMERO
            if (blacklistedTokenService.isFullTokenBlacklisted(refreshToken)) {
                logger.warn("🚫 Refresh token está en blacklist");
                return false;
            }

            // ✅ VERIFICAR FIRMA JWT
            DecodedJWT decodedJWT = verifier.verify(refreshToken);

            // ✅ VERIFICAR EXPIRACIÓN
            Date expirationDate = decodedJWT.getExpiresAt();
            if (expirationDate != null && expirationDate.before(new Date())) {
                logger.warn("⚠️ Refresh token expirado");
                removeToken(refreshToken);
                return false;
            }

            // ✅ VERIFICAR QUE EXISTE EN NUESTRO ALMACÉN
            boolean existsInStore = refreshTokenStore.containsKey(refreshToken);
            if (!existsInStore) {
                logger.warn("⚠️ Refresh token no encontrado en almacén");
                return false;
            }

            logger.debug("✅ Refresh token válido");
            return true;

        } catch (JWTVerificationException e) {
            logger.warn("❌ Refresh token inválido: {}", e.getMessage());
            removeToken(refreshToken); // Limpiar token inválido
            return false;
        }
    }

    /**
     * ✅ Validar ACCESS token (diferente de refresh token)
     */
    public boolean validateAccessToken(String accessToken) {
        try {
            // 🚫 VERIFICAR BLACKLIST PRIMERO
            if (blacklistedTokenService.isFullTokenBlacklisted(accessToken)) {
                logger.warn("🚫 Access token está en blacklist");
                return false;
            }

            // ✅ VERIFICAR FIRMA Y DECODIFICAR JWT
            DecodedJWT decodedJWT = verifier.verify(accessToken);

            // ✅ VERIFICAR QUE ES UN ACCESS TOKEN
            String tokenType = decodedJWT.getClaim("type").asString();
            if (!"access".equals(tokenType)) {
                logger.warn("⚠️ Token no es de tipo access: {}", tokenType);
                return false;
            }

            // ✅ VERIFICAR EXPIRACIÓN
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

    /**
     * 🔄 Generar nuevo refresh token
     */
    public String generateRefreshToken(String username) {
        try {
            String tokenId = UUID.randomUUID().toString();

            String refreshToken = JWT.create()
                    .withSubject(username)
                    .withClaim("tokenId", tokenId)
                    .withClaim("type", "refresh")
                    .withIssuedAt(new Date())
                    .withExpiresAt(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                    .sign(algorithm);

            // 💾 GUARDAR EN ALMACÉN
            saveToken(refreshToken, username);

            logger.debug("🔄 Refresh token generado para usuario: {}", username);
            return refreshToken;

        } catch (Exception e) {
            logger.error("❌ Error generando refresh token para usuario {}: {}", username, e.getMessage());
            throw new RuntimeException("Error generando refresh token", e);
        }
    }

    /**
     * 🎫 Generar nuevo access token CON AUTHORITIES
     * ✅ MÉTODO CORREGIDO PARA INCLUIR ROLES/AUTHORITIES
     */
    public String generateAccessToken(String username) {
        try {
            // ✅ CARGAR USER DETAILS PARA OBTENER AUTHORITIES
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // ✅ EXTRAER AUTHORITIES COMO LISTA DE STRINGS
            List<String> authorities = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            String accessToken = JWT.create()
                    .withSubject(username)
                    .withClaim("type", "access")
                    .withClaim("authorities", authorities) // ✅ NUEVO: Incluir authorities
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

    /**
     * 📤 Extraer refresh token de la request
     */
    public String extractRefreshTokenFromRequest(HttpServletRequest request) {
        // ✅ BUSCAR EN HEADER PRIMERO
        String refreshToken = request.getHeader("Refresh-Token");

        // ✅ BUSCAR EN PARÁMETROS SI NO ESTÁ EN HEADER
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            refreshToken = request.getParameter("refreshToken");
        }

        return refreshToken;
    }

    /**
     * 🧹 Limpiar tokens expirados (método utilitario)
     */
    public void cleanupExpiredTokens() {
        int initialSize = refreshTokenStore.size();

        refreshTokenStore.entrySet().removeIf(entry -> {
            String token = entry.getKey();
            try {
                DecodedJWT decodedJWT = verifier.verify(token);
                Date expirationDate = decodedJWT.getExpiresAt();
                if (expirationDate != null && expirationDate.before(new Date())) {
                    // 🚫 AGREGAR A BLACKLIST ANTES DE REMOVER
                    blacklistedTokenService.blacklistToken(token, "Expirado durante limpieza");
                    return true;
                }
                return false;
            } catch (JWTVerificationException e) {
                // Token inválido, remover y agregar a blacklist
                blacklistedTokenService.blacklistToken(token, "Inválido durante limpieza");
                return true;
            }
        });

        int removedTokens = initialSize - refreshTokenStore.size();
        if (removedTokens > 0) {
            logger.info("🧹 Limpieza completada: {} tokens expirados removidos y agregados a blacklist", removedTokens);
        }
    }

    /**
     * 🚫 Invalidar token específico (para logout)
     */
    public void invalidateToken(String refreshToken, String reason) {
        String username = refreshTokenStore.remove(refreshToken);
        if (username != null) {
            blacklistedTokenService.blacklistToken(refreshToken, reason);
            logger.info("🚫 Token invalidado para usuario: {} (razón: {})", username, reason);
        }
    }

    /**
     * 📊 Obtener estadísticas del servicio
     */
    public Map<String, Object> getStats() {
        BlacklistedTokenService.BlacklistStats blacklistStats = blacklistedTokenService.getStatistics();

        return Map.of(
                "activeRefreshTokens", refreshTokenStore.size(),
                "blacklistedTokens", blacklistStats.getTotalBlacklistedTokens(),
                "algorithmUsed", "HS512",
                "accessTokenExpirationMs", accessTokenExpiration,
                "refreshTokenExpirationMs", refreshTokenExpiration);
    }
}