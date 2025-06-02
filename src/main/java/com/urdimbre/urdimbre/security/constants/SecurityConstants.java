package com.urdimbre.urdimbre.security.constants;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import lombok.Getter;

@Component
@Getter
@SuppressWarnings({ "java:S1104", "java:S1444", "java:S3008", "java:S2696" }) // ✅ SUPRIMIR WARNINGS DE SONARLINT
public class SecurityConstants {

    // ✅ CAMPOS DE INSTANCIA CON LOMBOK
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token-expiration:86400000}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration:604800000}")
    private long refreshTokenExpiration;

    // ✅ CONSTANTES ESTÁTICAS (para compatibilidad con código existente)
    public static String SECRET;
    public static long EXPIRATION_TIME;
    public static long REFRESH_EXPIRATION_TIME;

    // Constantes que no cambian
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";

    @PostConstruct
    public void init() {
        // ✅ INICIALIZAR CONSTANTES ESTÁTICAS DESPUÉS DE INYECCIÓN
        SECRET = this.jwtSecret;
        EXPIRATION_TIME = this.accessTokenExpiration;
        REFRESH_EXPIRATION_TIME = this.refreshTokenExpiration;

        // Validaciones
        if (SECRET == null || SECRET.isEmpty()) {
            throw new IllegalStateException(
                    "JWT secret no configurado. Verifica jwt.secret en application.properties");
        }

        if (SECRET.length() < 32) {
            throw new IllegalStateException(
                    "JWT secret debe tener al menos 32 caracteres. Actual: " + SECRET.length());
        }
    }
}