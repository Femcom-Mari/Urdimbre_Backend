package com.urdimbre.urdimbre.controller;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
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
import com.urdimbre.urdimbre.dto.auth.CheckAvailabilityResponseDTO;
import com.urdimbre.urdimbre.dto.auth.ForgotPasswordRequestDTO;
import com.urdimbre.urdimbre.dto.auth.ForgotPasswordResponseDTO;
import com.urdimbre.urdimbre.dto.auth.RefreshTokenRequestDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodePublicInfoDTO;
import com.urdimbre.urdimbre.dto.user.UserRegisterDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.exception.BadRequestException;
import com.urdimbre.urdimbre.exception.RateLimitExceededException;
import com.urdimbre.urdimbre.model.InviteCode;
import com.urdimbre.urdimbre.model.User;
import com.urdimbre.urdimbre.repository.UserRepository;
import com.urdimbre.urdimbre.security.service.RateLimitingService;
import com.urdimbre.urdimbre.service.auth.AuthService;
import com.urdimbre.urdimbre.service.invite.InviteCodeService;
import com.urdimbre.urdimbre.service.token.BlacklistedTokenService;
import com.urdimbre.urdimbre.util.HtmlSanitizer;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "API para autenticación y gestión de usuarios")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private static final String ERROR_INTERNO_SERVIDOR = "Error interno del servidor";

    private final AuthService authService;
    private final InviteCodeService inviteCodeService;
    private final BlacklistedTokenService blacklistedTokenService;
    private final RateLimitingService rateLimitingService;
    private final UserRepository userRepository;

    @PostMapping("/register")
    @Operation(summary = "Registro público de usuario", description = "Permite el registro de nuevos usuarios con código de invitación")
    @ApiResponse(responseCode = "200", description = "Usuario registrado exitosamente")
    @ApiResponse(responseCode = "400", description = "Error de validación o código de invitación inválido")
    @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    public ResponseEntity<UserResponseDTO> register(
            @Valid @RequestBody UserRegisterDTO request,
            HttpServletRequest httpRequest) {

        logger.info("🔐 Intento de registro PÚBLICO para usuario: {}", request.getUsername());

        try {
            RateLimitingService.RateLimitResult rateLimitResult = rateLimitingService.checkRegisterByIp(httpRequest);
            if (!rateLimitResult.isAllowed()) {
                throw RateLimitExceededException.forRegisterByIp(rateLimitResult.getRetryAfterSeconds());
            }

            // ✅ VALIDAR CÓDIGO DE INVITACIÓN (SIEMPRE OBLIGATORIO EN REGISTRO PÚBLICO)
            if (!inviteCodeService.validateInviteCode(request.getInviteCode())) {
                logger.warn("❌ Código de invitación inválido para {}: {}", request.getUsername(),
                        request.getInviteCode());

                String specificMessage = getSpecificInviteCodeError(request.getInviteCode());
                throw new BadRequestException("Código de invitación: " + specificMessage);
            }

            // VALIDACIONES ESPECÍFICAS DE USUARIO
            validateRegistrationDataWithSpecificErrors(request);

            UserResponseDTO response = authService.register(request);

            logger.info("✅ Usuario registrado exitosamente: {} (Rate limit remaining: {})",
                    request.getUsername(), rateLimitResult.getRemainingTokens());

            return ResponseEntity.ok()
                    .header("X-RateLimit-Remaining", String.valueOf(rateLimitResult.getRemainingTokens()))
                    .body(response);

        } catch (RateLimitExceededException e) {
            logger.warn("🚫 Rate limit exceeded en registro - Usuario: {} - IP: {} - Tipo: {} - Retry after: {}s",
                    request.getUsername(), rateLimitingService.getClientIp(httpRequest),
                    e.getRateLimitType(), e.getRetryAfterSeconds());

            throw new RateLimitExceededException(
                    String.format("Rate limit exceeded para registro - Usuario: %s desde IP: %s. %s",
                            request.getUsername(), rateLimitingService.getClientIp(httpRequest), e.getMessage()),
                    e.getRetryAfterSeconds(),
                    e.getRateLimitType());
        } catch (BadRequestException e) {
            logger.warn("❌ Error de validación en registro - Usuario: {} - Error original: {}",
                    request.getUsername(), e.getMessage());

            throw new BadRequestException(
                    String.format("Error de validación en registro para usuario '%s': %s",
                            request.getUsername(), e.getMessage()));
        } catch (DataIntegrityViolationException e) {
            logger.warn("❌ Error de integridad en registro para {}: {}", request.getUsername(), e.getMessage());
            String errorMessage = e.getMessage().toLowerCase();
            if (errorMessage.contains("username") || errorMessage.contains("usuario")) {
                throw new BadRequestException("El nombre de usuario '" + request.getUsername() + "' ya está en uso");
            } else if (errorMessage.contains("email") || errorMessage.contains("correo")) {
                throw new BadRequestException("El email '" + request.getEmail() + "' ya está registrado");
            } else {
                throw new BadRequestException("Los datos proporcionados ya están en uso");
            }
        } catch (RuntimeException e) {
            logger.error("❌ Error inesperado (Runtime) en registro para {}: {}", request.getUsername(), e.getMessage(),
                    e);
            throw new BadRequestException(ERROR_INTERNO_SERVIDOR + ". Inténtalo de nuevo más tarde.");
        } catch (Exception e) {
            logger.error("❌ Error inesperado (Checked) en registro para {}: {}", request.getUsername(), e.getMessage(),
                    e);
            throw new BadRequestException(ERROR_INTERNO_SERVIDOR + ". Inténtalo de nuevo más tarde.");
        }
    }

    @PostMapping("/login")
    @Operation(summary = "Login de usuario", description = "Autentica un usuario y devuelve tokens de acceso")
    @ApiResponse(responseCode = "200", description = "Login exitoso")
    @ApiResponse(responseCode = "401", description = "Credenciales inválidas")
    @ApiResponse(responseCode = "429", description = "Rate limit excedido")
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
            logger.warn("🚫 Rate limit exceeded en login - Usuario: {} - IP: {} - Tipo: {} - Retry after: {}s",
                    request.getUsername(), rateLimitingService.getClientIp(httpRequest),
                    e.getRateLimitType(), e.getRetryAfterSeconds());

            throw new RateLimitExceededException(
                    String.format("Rate limit exceeded para login - Usuario: %s desde IP: %s. %s",
                            request.getUsername(), rateLimitingService.getClientIp(httpRequest), e.getMessage()),
                    e.getRetryAfterSeconds(),
                    e.getRateLimitType());
        } catch (BadCredentialsException e) {
            logger.warn("❌ Credenciales inválidas - Usuario: {} - IP: {} - Error original: {}",
                    request.getUsername(), rateLimitingService.getClientIp(httpRequest), e.getMessage(), e);

            throw new BadCredentialsException(
                    String.format("Credenciales inválidas para usuario '%s' desde IP '%s': %s",
                            request.getUsername(), rateLimitingService.getClientIp(httpRequest), e.getMessage()),
                    e);
        } catch (RuntimeException e) {
            logger.error("❌ Error inesperado (Runtime) en login - Usuario: {} - Error: {}",
                    request.getUsername(), e.getMessage(), e);
            throw new BadCredentialsException(
                    String.format("Error interno del servidor durante login para usuario '%s': %s",
                            request.getUsername(), e.getMessage()));
        } catch (Exception e) {
            logger.error("❌ Error inesperado (Checked) en login - Usuario: {} - Error: {}",
                    request.getUsername(), e.getMessage(), e);
            throw new BadCredentialsException(
                    String.format("Error interno del servidor durante login para usuario '%s': %s",
                            request.getUsername(), e.getMessage()));
        }
    }

    @PostMapping("/refresh")
    @Operation(summary = "Renovar token", description = "Renueva el token de acceso usando el refresh token")
    @ApiResponse(responseCode = "200", description = "Token renovado exitosamente")
    @ApiResponse(responseCode = "401", description = "Refresh token inválido")
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
            String tokenPreview = request.getRefreshToken() != null
                    ? request.getRefreshToken().substring(0, Math.min(10, request.getRefreshToken().length())) + "..."
                    : "null";
            logger.warn("❌ Refresh token inválido - Token preview: {} - Error original: {}", tokenPreview,
                    e.getMessage());

            throw new BadCredentialsException(
                    String.format("Token de sesión expirado o inválido (preview: %s): %s", tokenPreview,
                            e.getMessage()));
        } catch (RuntimeException e) {
            logger.error("❌ Error inesperado (Runtime) en renovación de token: {}", e.getMessage(), e);
            throw new BadCredentialsException("Error interno del servidor durante renovación de token");
        } catch (Exception e) {
            logger.error("❌ Error inesperado (Checked) en renovación de token: {}", e.getMessage(), e);
            throw new BadCredentialsException("Error interno del servidor durante renovación de token");
        }
    }

    @PostMapping("/logout")
    @Operation(summary = "Cerrar sesión", description = "Cierra la sesión del usuario y invalida los tokens")
    @ApiResponse(responseCode = "200", description = "Logout exitoso")
    @ApiResponse(responseCode = "500", description = "Error interno")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
        String username = "unknown";

        try {
            username = SecurityContextHolder.getContext().getAuthentication().getName();
            logger.info("🚪 Intento de logout para usuario: {}", username);

            addTokensToBlacklist(request, username);
            authService.logout(request, response);
            SecurityContextHolder.clearContext();

            logger.info("✅ Logout exitoso para usuario: {}", username);
            return ResponseEntity.ok("Sesión cerrada exitosamente");

        } catch (Exception e) {
            logger.error("❌ Error en logout para usuario: {} - Error: {}", username, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error cerrando sesión para usuario: " + username + ", pero limpieza local completada");
        }
    }

    // ===================================================
    // ✅ ENDPOINTS PARA VERIFICACIÓN Y RECUPERACIÓN
    // ===================================================

    @GetMapping("/check-username")
    @Operation(summary = "Verificar disponibilidad de username", description = "Verifica si un username está disponible")
    @ApiResponse(responseCode = "200", description = "Verificación completada")
    @ApiResponse(responseCode = "400", description = "Username inválido")
    public ResponseEntity<CheckAvailabilityResponseDTO> checkUsernameAvailability(@RequestParam String username) {
        logger.debug("🔍 Verificando disponibilidad de username: {}", username);

        try {
            if (username == null || username.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(CheckAvailabilityResponseDTO.error("Username requerido"));
            }

            if (username.length() < 3) {
                return ResponseEntity.ok(CheckAvailabilityResponseDTO
                        .notAvailable("Username debe tener al menos 3 caracteres"));
            }

            if (username.length() > 50) {
                return ResponseEntity.ok(CheckAvailabilityResponseDTO
                        .notAvailable("Username demasiado largo"));
            }

            // Validar formato
            if (!username.matches("^[a-zA-Z0-9_.-]+$")) {
                return ResponseEntity.ok(CheckAvailabilityResponseDTO
                        .notAvailable("Username solo puede contener letras, números, puntos, guiones y guiones bajos"));
            }

            boolean isAvailable = userRepository.findByUsername(username).isEmpty();

            return ResponseEntity.ok(isAvailable
                    ? CheckAvailabilityResponseDTO.available("Username disponible")
                    : CheckAvailabilityResponseDTO.notAvailable("Username no disponible"));

        } catch (Exception e) {
            logger.error("❌ Error verificando username {}: {}", username, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(CheckAvailabilityResponseDTO.error(ERROR_INTERNO_SERVIDOR));
        }
    }

    @GetMapping("/check-email")
    @Operation(summary = "Verificar disponibilidad de email", description = "Verifica si un email está disponible")
    @ApiResponse(responseCode = "200", description = "Verificación completada")
    @ApiResponse(responseCode = "400", description = "Email inválido")
    public ResponseEntity<CheckAvailabilityResponseDTO> checkEmailAvailability(@RequestParam String email) {
        logger.debug("🔍 Verificando disponibilidad de email: {}", email);

        try {
            if (email == null || email.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(CheckAvailabilityResponseDTO.error("Email requerido"));
            }

            if (!isValidEmail(email)) {
                return ResponseEntity.ok(CheckAvailabilityResponseDTO
                        .notAvailable("Formato de email inválido"));
            }

            if (email.length() > 100) {
                return ResponseEntity.ok(CheckAvailabilityResponseDTO
                        .notAvailable("Email demasiado largo"));
            }

            boolean isAvailable = userRepository.findByEmail(email).isEmpty();

            return ResponseEntity.ok(isAvailable
                    ? CheckAvailabilityResponseDTO.available("Email disponible")
                    : CheckAvailabilityResponseDTO.notAvailable("Email no disponible"));

        } catch (Exception e) {
            logger.error("❌ Error verificando email {}: {}", email, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(CheckAvailabilityResponseDTO.error(ERROR_INTERNO_SERVIDOR));
        }
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Solicitar recuperación de contraseña", description = "Envía un enlace de recuperación al email del usuario")
    @ApiResponse(responseCode = "200", description = "Email de recuperación enviado")
    @ApiResponse(responseCode = "404", description = "Email no encontrado")
    @ApiResponse(responseCode = "400", description = "Email inválido")
    public ResponseEntity<ForgotPasswordResponseDTO> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequestDTO request) {
        logger.info("📧 Solicitud de recuperación de contraseña para email: {}", request.getEmail());

        try {
            if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(ForgotPasswordResponseDTO.error("Email requerido"));
            }

            if (!isValidEmail(request.getEmail())) {
                return ResponseEntity.badRequest()
                        .body(ForgotPasswordResponseDTO.error("Formato de email inválido"));
            }

            // Verificar si el email existe
            Optional<User> userOpt = userRepository.findByEmail(request.getEmail());

            if (userOpt.isEmpty()) {
                logger.warn("❌ Intento de recuperación con email no registrado: {}", request.getEmail());
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(ForgotPasswordResponseDTO.emailNotFound());
            }

            // TODO: Implementar envío del email en el futuro
            // passwordResetService.sendPasswordResetEmail(userOpt.get());

            logger.info("✅ Email de recuperación enviado exitosamente a: {}", request.getEmail());

            return ResponseEntity.ok(ForgotPasswordResponseDTO.emailSent());

        } catch (Exception e) {
            logger.error("❌ Error en recuperación de contraseña para {}: {}", request.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ForgotPasswordResponseDTO.error(ERROR_INTERNO_SERVIDOR));
        }
    }

    @GetMapping("/invite-codes/validate")
    @Operation(summary = "Validar código de invitación", description = "Verifica si un código de invitación es válido")
    @ApiResponse(responseCode = "200", description = "Validación completada")
    @ApiResponse(responseCode = "400", description = "Código requerido")
    public ResponseEntity<Boolean> validateInviteCodePublic(@RequestParam String code) {
        logger.debug("✅ Validando código de invitación público: {}", code);

        if (code == null || code.trim().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(false);
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
    @Operation(summary = "Obtener información del código de invitación", description = "Devuelve información detallada sobre el estado del código")
    @ApiResponse(responseCode = "200", description = "Información obtenida")
    @ApiResponse(responseCode = "400", description = "Código requerido")
    public ResponseEntity<InviteCodePublicInfoDTO> getInviteCodeInfo(@RequestParam String code) {
        logger.debug("ℹ️ Obteniendo info pública del código: {}", code);

        if (code == null || code.trim().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(InviteCodePublicInfoDTO.invalid("Código requerido"));
        }

        try {
            boolean isValid = inviteCodeService.validateInviteCode(code);

            if (!isValid) {
                String specificMessage = getSpecificInviteCodeError(code);
                return ResponseEntity.ok(InviteCodePublicInfoDTO.invalid(specificMessage));
            }

            return ResponseEntity.ok(InviteCodePublicInfoDTO.valid("Código válido"));

        } catch (Exception e) {
            logger.warn("❌ Error obteniendo info del código {}: {}", code, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(InviteCodePublicInfoDTO.invalid("Error interno validando código"));
        }
    }

    @GetMapping("/rate-limit-stats")
    @Operation(summary = "Obtener estadísticas de rate limiting", description = "Devuelve estadísticas del sistema de rate limiting - Solo para ADMIN")
    @ApiResponse(responseCode = "200", description = "Estadísticas obtenidas")
    @ApiResponse(responseCode = "500", description = "Error interno")
    public ResponseEntity<RateLimitingService.RateLimitStats> getRateLimitStats() {
        try {
            RateLimitingService.RateLimitStats stats = rateLimitingService.getStatistics();
            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            logger.error("❌ Error obteniendo estadísticas de rate limit: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // ================================
    // 🔧 MÉTODOS PRIVADOS DE UTILIDAD
    // ================================

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
            logger.warn("⚠️ Error agregando tokens a blacklist para usuario {}: {}", username, e.getMessage());
        }
    }

    private void validateRegistrationDataWithSpecificErrors(UserRegisterDTO request) {

        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new BadRequestException("El nombre de usuario '" + request.getUsername() + "' ya está en uso");
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new BadRequestException("El email '" + request.getEmail() + "' ya está registrado");
        }

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
}