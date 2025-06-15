package com.urdimbre.urdimbre.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
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
import com.urdimbre.urdimbre.exception.RateLimitExceededException;
import com.urdimbre.urdimbre.model.InviteCode;
import com.urdimbre.urdimbre.repository.UserRepository;
import com.urdimbre.urdimbre.security.service.RateLimitingService;
import com.urdimbre.urdimbre.service.auth.AuthService;
import com.urdimbre.urdimbre.service.invite.InviteCodeService;
import com.urdimbre.urdimbre.service.token.BlacklistedTokenService;
import com.urdimbre.urdimbre.util.HtmlSanitizer;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final InviteCodeService inviteCodeService;
    private final BlacklistedTokenService blacklistedTokenService;
    private final RateLimitingService rateLimitingService;
    private final UserRepository userRepository;

    @PostMapping("/register")
    public ResponseEntity<UserResponseDTO> register(
            @Valid @RequestBody UserRegisterDTO request,
            HttpServletRequest httpRequest) {

        logger.info("🔐 Intento de registro para usuario: {}", request.getUsername());

        try {
            // ✅ RATE LIMITING
            RateLimitingService.RateLimitResult rateLimitResult = rateLimitingService.checkRegisterByIp(httpRequest);
            if (!rateLimitResult.isAllowed()) {
                throw RateLimitExceededException.forRegisterByIp(rateLimitResult.getRetryAfterSeconds());
            }

            // ✅ VALIDACIÓN ESPECÍFICA DEL CÓDIGO DE INVITACIÓN
            if (!inviteCodeService.validateInviteCode(request.getInviteCode())) {
                logger.warn("❌ Código de invitación inválido para {}: {}", request.getUsername(),
                        request.getInviteCode());

                // ✅ VERSIÓN CORREGIDA - SIN RECURSIÓN
                String specificMessage = getSpecificInviteCodeError(request.getInviteCode());
                throw new BadRequestException("Código de invitación: " + specificMessage);
            }

            // ✅ VALIDACIONES ESPECÍFICAS DE USUARIO
            validateRegistrationDataWithSpecificErrors(request);

            UserResponseDTO response = authService.register(request);

            logger.info("✅ Usuario registrado exitosamente: {} (Rate limit remaining: {})",
                    request.getUsername(), rateLimitResult.getRemainingTokens());

            return ResponseEntity.ok()
                    .header("X-RateLimit-Remaining", String.valueOf(rateLimitResult.getRemainingTokens()))
                    .body(response);

        } catch (RateLimitExceededException e) {
            logger.warn("🚫 Rate limit exceeded en registro para IP: {}",
                    rateLimitingService.getClientIp(httpRequest));
            throw e;
        } catch (BadRequestException e) {
            logger.warn("❌ Error en registro para {}: {}", request.getUsername(), e.getMessage());
            throw e; // Re-lanzar con el mensaje específico
        } catch (DataIntegrityViolationException e) {
            logger.warn("❌ Error de integridad en registro para {}: {}", request.getUsername(), e.getMessage());

            // ✅ MANEJO ESPECÍFICO DE ERRORES DE DUPLICACIÓN
            String errorMessage = e.getMessage().toLowerCase();
            if (errorMessage.contains("username")) {
                throw new BadRequestException("El nombre de usuario '" + request.getUsername() + "' ya está en uso");
            } else if (errorMessage.contains("email")) {
                throw new BadRequestException("El email '" + request.getEmail() + "' ya está registrado");
            } else {
                throw new BadRequestException("Los datos proporcionados ya están en uso");
            }
        } catch (Exception e) {
            logger.error("❌ Error inesperado en registro para {}: {}", request.getUsername(), e.getMessage(), e);
            throw new BadRequestException("Error interno del servidor. Inténtalo de nuevo más tarde.");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(
            @Valid @RequestBody AuthRequestDTO request,
            HttpServletRequest httpRequest) {

        logger.info("🔑 Intento de login para: {}", request.getUsername());

        try {
            validateLoginData(request);

            RateLimitingService.RateLimitResult ipRateLimit = rateLimitingService.checkLoginByIp(httpRequest);
            if (!ipRateLimit.isAllowed()) {
                throw RateLimitExceededException.forLoginByIp(ipRateLimit.getRetryAfterSeconds());
            }

            RateLimitingService.RateLimitResult userRateLimit = rateLimitingService
                    .checkLoginByUser(request.getUsername());
            if (!userRateLimit.isAllowed()) {
                throw RateLimitExceededException.forLoginByUser(request.getUsername(),
                        userRateLimit.getRetryAfterSeconds());
            }

            AuthResponseDTO response = authService.login(request);

            logger.info("✅ Login exitoso para usuario: {} (IP remaining: {}, User remaining: {})",
                    request.getUsername(), ipRateLimit.getRemainingTokens(), userRateLimit.getRemainingTokens());

            return ResponseEntity.ok()
                    .header("X-RateLimit-IP-Remaining", String.valueOf(ipRateLimit.getRemainingTokens()))
                    .header("X-RateLimit-User-Remaining", String.valueOf(userRateLimit.getRemainingTokens()))
                    .body(response);

        } catch (RateLimitExceededException e) {
            logger.warn("🚫 Rate limit exceeded en login para usuario: {} desde IP: {}",
                    request.getUsername(), rateLimitingService.getClientIp(httpRequest));
            throw e;
        } catch (BadCredentialsException e) {
            logger.warn("❌ Credenciales inválidas para: {}. Detalle: {}", request.getUsername(), e.getMessage());
            throw new BadCredentialsException("Credenciales inválidas. Verifica tu usuario y contraseña.");
        } catch (Exception e) {
            logger.error("❌ Error inesperado en login para {}: {}", request.getUsername(), e.getMessage(), e);
            throw new BadCredentialsException("Error interno del servidor. Inténtalo de nuevo más tarde.");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDTO> refreshToken(@Valid @RequestBody RefreshTokenRequestDTO request) {
        logger.info("🔄 Intento de renovación de token");

        try {
            if (request.getRefreshToken() == null || request.getRefreshToken().trim().isEmpty()) {
                throw new BadCredentialsException("Refresh token es requerido");
            }

            if (blacklistedTokenService.isTokenBlacklisted(request.getRefreshToken())) {
                logger.warn("❌ Intento de usar refresh token en blacklist");
                throw new BadCredentialsException("Token inválido");
            }

            AuthResponseDTO response = authService.refreshToken(request.getRefreshToken());

            logger.info("✅ Token renovado exitosamente para usuario: {}", response.getUsername());
            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            logger.warn("❌ Refresh token inválido: {}", e.getMessage());
            throw new BadCredentialsException("Token de sesión expirado. Por favor, inicia sesión nuevamente.");
        } catch (Exception e) {
            logger.error("❌ Error inesperado en renovación de token: {}", e.getMessage());
            throw new BadCredentialsException("Error interno del servidor durante la renovación de token");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            String username = SecurityContextHolder.getContext().getAuthentication().getName();
            logger.info("🚪 Intento de logout para usuario: {}", username);

            addTokensToBlacklist(request, username);

            authService.logout(request, response);

            SecurityContextHolder.clearContext();

            logger.info("✅ Logout exitoso para usuario: {}", username);
            return ResponseEntity.ok("Sesión cerrada exitosamente");

        } catch (Exception e) {
            logger.error("❌ Error en logout: {}", e.getMessage());
            return ResponseEntity.status(org.springframework.http.HttpStatus.OK).body("Sesión cerrada");
        }
    }

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
            boolean isValid = inviteCodeService.validateInviteCode(code);

            if (!isValid) {
                String specificMessage = getSpecificInviteCodeError(code);
                return ResponseEntity.ok(InviteCodePublicInfo.builder()
                        .valid(false)
                        .message(specificMessage)
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

    @GetMapping("/rate-limit-stats")
    public ResponseEntity<RateLimitingService.RateLimitStats> getRateLimitStats() {
        RateLimitingService.RateLimitStats stats = rateLimitingService.getStatistics();
        return ResponseEntity.ok(stats);
    }

    // ===================================================
    // MÉTODOS PRIVADOS DE VALIDACIÓN Y UTILIDADES
    // ===================================================

    // ✅ MÉTODO CORREGIDO PARA OBTENER INFORMACIÓN ESPECÍFICA DEL CÓDIGO
    private String getSpecificInviteCodeError(String code) {
        try {
            Optional<InviteCode> optionalCode = inviteCodeService.findByCode(code);

            if (optionalCode.isEmpty()) {
                return "Código no encontrado";
            }

            InviteCode inviteCode = optionalCode.get();

            if (inviteCode.isExpired()) {
                return "Código expirado";
            } else if (inviteCode.isMaxUsesReached()) {
                return "Código agotado (máximo de usos alcanzado)";
            } else {
                return "Código inválido";
            }

        } catch (Exception e) {
            logger.warn("❌ Error obteniendo detalles del código {}: {}", code, e.getMessage());
            return "Código inválido";
        }
    }

    private void addTokensToBlacklist(HttpServletRequest request, String username) {
        try {
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String accessToken = authHeader.substring(7);
                blacklistedTokenService.blacklistToken(
                        accessToken, username, "access",
                        java.time.LocalDateTime.now().plusMinutes(15),
                        "Logout manual");
            }

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

    // ✅ MÉTODO DE VALIDACIÓN CON ERRORES ESPECÍFICOS
    private void validateRegistrationDataWithSpecificErrors(UserRegisterDTO request) {
        // Validar username duplicado
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new BadRequestException("El nombre de usuario '" + request.getUsername() + "' ya está en uso");
        }

        // Validar email duplicado
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new BadRequestException("El email '" + request.getEmail() + "' ya está registrado");
        }

        // Continuar con validaciones existentes...
        validateUsername(request.getUsername());
        validateEmail(request.getEmail());
        validatePassword(request.getPassword());
        validateFullName(request.getFullName()); // ✅ ESTE MÉTODO DEBE EXISTIR EN UserRegisterDTO
        validateInviteCode(request.getInviteCode());
    }

    private void validateUsername(String username) {
        if (username == null || username.trim().length() < 3) {
            throw new BadRequestException("El username debe tener al menos 3 caracteres");
        }
        if (username.length() > 50) {
            throw new BadRequestException("El username no puede tener más de 50 caracteres");
        }

        String sanitized = HtmlSanitizer.sanitizeUserInput(username);
        if (!sanitized.equals(username)) {
            logger.warn("🚨 Intento de inyección HTML en username: {}", username);
            throw new BadRequestException("Username contiene caracteres no permitidos");
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

        if (!HtmlSanitizer.isSafeContent(email)) {
            logger.warn("🚨 Intento de inyección en email: {}", email);
            throw new BadRequestException("Email contiene contenido no permitido");
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
                    "La contraseña debe contener al menos una mayúscula, una minúscula, un número y un símbolo (@$!%*?&)");
        }
    }

    private void validateFullName(String fullName) {
        if (fullName == null || fullName.trim().length() < 2) {
            throw new BadRequestException("El nombre completo debe tener al menos 2 caracteres");
        }
        if (fullName.length() > 100) {
            throw new BadRequestException("El nombre completo no puede tener más de 100 caracteres");
        }

        String sanitized = HtmlSanitizer.sanitizeUserInput(fullName);
        if (!sanitized.equals(fullName)) {
            logger.warn("🚨 Intento de inyección HTML en fullName: {}", fullName);
            throw new BadRequestException("Nombre completo contiene caracteres no permitidos");
        }
    }

    private void validateInviteCode(String inviteCode) {
        if (inviteCode == null || inviteCode.trim().isEmpty()) {
            throw new BadRequestException("Código de invitación es obligatorio");
        }
    }

    private void validateLoginData(AuthRequestDTO request) {
        if (request.getUsername() == null || request.getUsername().trim().isEmpty()) {
            throw new BadCredentialsException("Username o email es requerido");
        }

        if (request.getUsername().length() > 100) {
            throw new BadCredentialsException("Username/email demasiado largo");
        }

        if (request.getPassword() == null || request.getPassword().trim().isEmpty()) {
            throw new BadCredentialsException("Contraseña es requerida");
        }

        if (request.getPassword().length() > 128) {
            throw new BadCredentialsException("Contraseña demasiado larga");
        }
    }

    private boolean isValidEmail(String email) {
        return email != null && email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }

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

    @lombok.Builder
    @lombok.Data
    public static class InviteCodePublicInfo {
        private boolean valid;
        private String message;
    }
}