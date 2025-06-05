package com.urdimbre.urdimbre.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.dto.auth.AuthRequestDTO;
import com.urdimbre.urdimbre.dto.auth.AuthResponseDTO;
import com.urdimbre.urdimbre.dto.auth.RefreshTokenRequestDTO;
import com.urdimbre.urdimbre.dto.user.UserRegisterDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.exception.BadRequestException;
import com.urdimbre.urdimbre.service.auth.AuthService;
import com.urdimbre.urdimbre.service.invite.InviteCodeService;
import com.urdimbre.urdimbre.service.token.BlacklistedTokenService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final InviteCodeService inviteCodeService;
    private final BlacklistedTokenService blacklistedTokenService;

    /**
     * 📝 Registro de usuario CON CÓDIGO DE INVITACIÓN DINÁMICO
     */
    @PostMapping("/register")
    public ResponseEntity<UserResponseDTO> register(@Valid @RequestBody UserRegisterDTO request) {
        logger.info("🔐 Intento de registro para usuario: {}", request.getUsername());

        try {
            // 🎟️ VALIDAR CÓDIGO DE INVITACIÓN ANTES DEL REGISTRO
            // ✅ CAMBIO: Solo validar, no usar aquí (AuthService lo usará después)
            if (!inviteCodeService.validateInviteCode(request.getInviteCode())) {
                throw new BadRequestException("Código de invitación inválido, expirado o agotado");
            }

            // 🔐 VALIDACIONES ADICIONALES DE SEGURIDAD
            validateRegistrationData(request);

            // 📝 PROCEDER CON EL REGISTRO (AuthService validará y usará el código)
            UserResponseDTO response = authService.register(request);

            logger.info("✅ Usuario registrado exitosamente: {}", request.getUsername());
            return ResponseEntity.ok(response);

        } catch (BadRequestException e) {
            logger.warn("❌ Error en registro para {}: {}", request.getUsername(), e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("❌ Error inesperado en registro para {}: {}", request.getUsername(), e.getMessage());
            throw new BadRequestException("Error interno del servidor");
        }
    }

    /**
     * 🔑 Login de usuario
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(@Valid @RequestBody AuthRequestDTO request) {
        logger.info("🔑 Intento de login para: {}", request.getUsername());

        try {
            // 🔐 VALIDACIONES DE SEGURIDAD
            validateLoginData(request);

            // 🔑 PROCEDER CON EL LOGIN
            AuthResponseDTO response = authService.login(request);

            logger.info("✅ Login exitoso para usuario: {}", request.getUsername());
            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            logger.warn("❌ Credenciales inválidas para: {}. Detalle: {}", request.getUsername(), e.getMessage(), e);
            throw new BadCredentialsException(
                    "Credenciales inválidas para usuario: " + request.getUsername() + ". Detalle: " + e.getMessage(),
                    e);
        } catch (Exception e) {
            logger.error("❌ Error inesperado en login para {}: {}", request.getUsername(), e.getMessage(), e);
            throw new BadCredentialsException("Error interno del servidor para usuario: " + request.getUsername()
                    + ". Detalle: " + e.getMessage(), e);
        }
    }

    /**
     * 🔄 Renovar token de acceso
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDTO> refreshToken(@Valid @RequestBody RefreshTokenRequestDTO request) {
        logger.info("🔄 Intento de renovación de token");

        try {
            // 🔐 VALIDAR REFRESH TOKEN
            if (request.getRefreshToken() == null || request.getRefreshToken().trim().isEmpty()) {
                throw new BadCredentialsException("Refresh token es requerido");
            }

            // 🚫 VERIFICAR QUE NO ESTÉ EN BLACKLIST
            if (blacklistedTokenService.isTokenBlacklisted(request.getRefreshToken())) {
                logger.warn("❌ Intento de usar refresh token en blacklist");
                throw new BadCredentialsException("Token inválido");
            }

            // 🔄 PROCEDER CON LA RENOVACIÓN
            AuthResponseDTO response = authService.refreshToken(request.getRefreshToken());

            logger.info("✅ Token renovado exitosamente para usuario: {}", response.getUsername());
            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            logger.warn("❌ Refresh token inválido: {}", e.getMessage());
            throw new BadCredentialsException("Refresh token inválido: " + e.getMessage());
        } catch (Exception e) {
            logger.error("❌ Error inesperado en renovación de token: {}", e.getMessage());
            throw new BadCredentialsException("Error interno del servidor durante la renovación de token");
        }
    }

    /**
     * 🚪 Cerrar sesión CON BLACKLIST
     */
    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            String username = SecurityContextHolder.getContext().getAuthentication().getName();
            logger.info("🚪 Intento de logout para usuario: {}", username);

            // 🚫 AGREGAR TOKENS A BLACKLIST
            addTokensToBlacklist(request, username);

            // 🚪 PROCEDER CON EL LOGOUT
            authService.logout(request, response);

            // 🧹 LIMPIAR CONTEXTO DE SEGURIDAD
            SecurityContextHolder.clearContext();

            logger.info("✅ Logout exitoso para usuario: {}", username);
            return ResponseEntity.ok("Sesión cerrada exitosamente");

        } catch (Exception e) {
            logger.error("❌ Error en logout: {}", e.getMessage());
            return ResponseEntity.status(org.springframework.http.HttpStatus.OK).body("Sesión cerrada"); // Siempre
                                                                                                         // confirmar
                                                                                                         // logout por
                                                                                                         // seguridad
        }
    }

    // ================================
    // ✅ NUEVOS ENDPOINTS PÚBLICOS PARA CÓDIGOS DE INVITACIÓN
    // ================================

    /**
     * ✅ Validar código de invitación (PÚBLICO - para frontend)
     * Este endpoint NO requiere autenticación
     */
    @GetMapping("/invite-codes/validate")
    public ResponseEntity<Boolean> validateInviteCodePublic(@RequestParam String code) {
        logger.debug("✅ Validando código de invitación público: {}", code);

        if (code == null || code.trim().isEmpty()) {
            return ResponseEntity.ok(false);
        }

        try {
            boolean isValid = inviteCodeService.validateInviteCode(code);
            logger.debug("✅ Código {} es válido: {}", code, isValid);
            return ResponseEntity.ok(isValid);
        } catch (Exception e) {
            logger.warn("❌ Error validando código {}: {}", code, e.getMessage());
            return ResponseEntity.ok(false);
        }
    }

    /**
     * ℹ️ Obtener información básica del código (sin datos sensibles)
     * Útil para mostrar al usuario si el código es válido antes del registro
     */
    @GetMapping("/invite-codes/info")
    public ResponseEntity<InviteCodePublicInfo> getInviteCodeInfo(@RequestParam String code) {
        logger.debug("ℹ️ Obteniendo info pública del código: {}", code);

        if (code == null || code.trim().isEmpty()) {
            return ResponseEntity.ok(InviteCodePublicInfo.builder()
                    .valid(false)
                    .message("Código requerido")
                    .build());
        }

        try {
            // Validar que el código existe y está activo
            boolean isValid = inviteCodeService.validateInviteCode(code);

            if (!isValid) {
                return ResponseEntity.ok(InviteCodePublicInfo.builder()
                        .valid(false)
                        .message("Código inválido o expirado")
                        .build());
            }

            return ResponseEntity.ok(InviteCodePublicInfo.builder()
                    .valid(true)
                    .message("Código válido")
                    .build());

        } catch (Exception e) {
            logger.warn("❌ Error obteniendo info del código {}: {}", code, e.getMessage());
            return ResponseEntity.status(org.springframework.http.HttpStatus.BAD_REQUEST).body(
                    InviteCodePublicInfo.builder()
                            .valid(false)
                            .message("Error validando código")
                            .build());
        }
    }

    // ================================
    // MÉTODOS PRIVADOS
    // ================================

    /**
     * 🚫 Agregar tokens a blacklist durante logout
     */
    private void addTokensToBlacklist(HttpServletRequest request, String username) {
        try {
            // 🎫 OBTENER ACCESS TOKEN DEL HEADER
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String accessToken = authHeader.substring(7);
                blacklistedTokenService.blacklistToken(
                        accessToken, username, "access",
                        java.time.LocalDateTime.now().plusMinutes(15),
                        "Logout manual");
            }

            // 🔄 OBTENER REFRESH TOKEN
            String refreshToken = request.getHeader("Refresh-Token");
            if (refreshToken != null && !refreshToken.trim().isEmpty()) {
                blacklistedTokenService.blacklistToken(
                        refreshToken, username, "refresh",
                        java.time.LocalDateTime.now().plusDays(7),
                        "Logout manual");
            }

            logger.debug("🚫 Tokens agregados a blacklist para usuario: {}", username);

        } catch (Exception e) {
            logger.warn("⚠️ Error agregando tokens a blacklist: {}", e.getMessage());
        }
    }

    /**
     * 🔍 Validar datos de registro
     */
    private void validateRegistrationData(UserRegisterDTO request) {
        validateUsername(request.getUsername());
        validateEmail(request.getEmail());
        validatePassword(request.getPassword());
        validateFullName(request.getFullName());
        validateInviteCode(request.getInviteCode());
    }

    private void validateUsername(String username) {
        if (username == null || username.trim().length() < 3) {
            throw new BadRequestException("El username debe tener al menos 3 caracteres");
        }
        if (username.length() > 50) {
            throw new BadRequestException("El username no puede tener más de 50 caracteres");
        }
        if (!username.matches("^[a-zA-Z0-9_.-]+$")) {
            throw new BadRequestException(
                    "El username solo puede contener letras, números, puntos, guiones y guiones bajos");
        }
    }

    private void validateEmail(String email) {
        if (email == null || !isValidEmail(email)) {
            throw new BadRequestException("Email inválido");
        }
        if (email.length() > 100) {
            throw new BadRequestException("Email demasiado largo");
        }
    }

    private void validatePassword(String password) {
        if (password == null || password.length() < 8) {
            throw new BadRequestException("La contraseña debe tener al menos 8 caracteres");
        }
        if (password.length() > 128) {
            throw new BadRequestException("La contraseña no puede tener más de 128 caracteres");
        }
        if (!isPasswordSecure(password)) {
            throw new BadRequestException(
                    "La contraseña debe contener al menos una mayúscula, una minúscula, un número y un símbolo");
        }
    }

    private void validateFullName(String fullName) {
        if (fullName == null || fullName.trim().length() < 2) {
            throw new BadRequestException("El nombre completo debe tener al menos 2 caracteres");
        }
        if (fullName.length() > 100) {
            throw new BadRequestException("El nombre completo no puede tener más de 100 caracteres");
        }
    }

    private void validateInviteCode(String inviteCode) {
        if (inviteCode == null || inviteCode.trim().isEmpty()) {
            throw new BadRequestException("Código de invitación es obligatorio");
        }
    }

    /**
     * 🔍 Validar datos de login
     */
    private void validateLoginData(AuthRequestDTO request) {
        // ✅ VALIDAR USERNAME/EMAIL
        if (request.getUsername() == null || request.getUsername().trim().isEmpty()) {
            throw new BadCredentialsException("Username o email es requerido");
        }

        if (request.getUsername().length() > 100) {
            throw new BadCredentialsException("Username/email demasiado largo");
        }

        // ✅ VALIDAR CONTRASEÑA
        if (request.getPassword() == null || request.getPassword().trim().isEmpty()) {
            throw new BadCredentialsException("Contraseña es requerida");
        }

        if (request.getPassword().length() > 128) {
            throw new BadCredentialsException("Contraseña demasiado larga");
        }
    }

    /**
     * 📧 Validar formato de email
     */
    private boolean isValidEmail(String email) {
        return email != null && email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }

    /**
     * 🔐 Validar que la contraseña sea segura
     */
    private boolean isPasswordSecure(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSymbol = password.chars().anyMatch(ch -> "@$!%*?&".indexOf(ch) >= 0);

        return hasLower && hasUpper && hasDigit && hasSymbol;
    }

    // ================================
    // DTO INTERNO PARA INFORMACIÓN PÚBLICA
    // ================================

    @lombok.Builder
    @lombok.Data
    public static class InviteCodePublicInfo {
        private boolean valid;
        private String message;
        // Podrías agregar más campos como:
        // private Integer remainingUses;
        // private Long hoursUntilExpiration;
    }
}