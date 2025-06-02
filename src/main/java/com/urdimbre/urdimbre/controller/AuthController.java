package com.urdimbre.urdimbre.controller;

import java.util.HashSet;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.dto.auth.AuthRequestDTO;
import com.urdimbre.urdimbre.dto.auth.AuthResponseDTO;
import com.urdimbre.urdimbre.dto.auth.RefreshTokenRequestDTO;
import com.urdimbre.urdimbre.dto.user.UserRegisterDTO;
import com.urdimbre.urdimbre.exception.BadRequestException;
import com.urdimbre.urdimbre.model.Role;
import com.urdimbre.urdimbre.model.User;
import com.urdimbre.urdimbre.model.User.UserStatus;
import com.urdimbre.urdimbre.repository.RoleRepository;
import com.urdimbre.urdimbre.repository.UserRepository;
import com.urdimbre.urdimbre.service.token.RefreshTokenService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    // Código temporal hasta implementar sistema dinámico
    private static final String VALID_INVITE_CODE = System.getenv("INVITE_CODE") != null ? System.getenv("INVITE_CODE")
            : "URDIMBRE2025";

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDTO> register(@Valid @RequestBody UserRegisterDTO request) {
        log.info("Registration attempt for user: {}", request.getUsername());

        // Validar código de invitación
        if (!VALID_INVITE_CODE.equals(request.getInviteCode())) {
            log.warn("Invalid invite code attempt for user: {}", request.getUsername());
            throw new BadRequestException("Código de invitación inválido");
        }

        // Verificar si el usuario ya existe
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            log.warn("Username already exists: {}", request.getUsername());
            throw new BadRequestException("El nombre de usuario ya está en uso");
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            log.warn("Email already exists: {}", request.getEmail());
            throw new BadRequestException("El email ya está en uso");
        }

        // Crear nuevo usuario - USANDO CAMPOS QUE EXISTEN EN TU MODELO
        User newUser = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .fullName(request.getFullName()) // fullName en lugar de firstName/lastName
                .status(UserStatus.ACTIVE)
                .biography("Nuevo usuario")
                .roles(new HashSet<>())
                .build();

        // Asignar rol por defecto
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Rol ROLE_USER no encontrado"));
        newUser.getRoles().add(userRole);

        // Guardar usuario
        User savedUser = userRepository.save(newUser);
        log.info("User registered successfully: {}", savedUser.getUsername());

        // Generar tokens - USANDO MÉTODOS QUE EXISTEN
        String accessToken = refreshTokenService.generateAccessToken(savedUser.getUsername());
        String refreshToken = refreshTokenService.generateRefreshToken(savedUser.getUsername());

        AuthResponseDTO response = AuthResponseDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .username(savedUser.getUsername())
                .email(savedUser.getEmail())
                .fullName(savedUser.getFullName())
                .build();

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(@Valid @RequestBody AuthRequestDTO request) {
        log.info("Login attempt for user: {}", request.getUsername());

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> {
                    log.warn("User not found: {}", request.getUsername());
                    return new BadRequestException("Credenciales inválidas");
                });

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            log.warn("Invalid password for user: {}", request.getUsername());
            throw new BadRequestException("Credenciales inválidas");
        }

        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user attempted login: {}", request.getUsername());
            throw new BadRequestException("Usuario inactivo");
        }

        // Generar tokens
        String accessToken = refreshTokenService.generateAccessToken(user.getUsername());
        String refreshToken = refreshTokenService.generateRefreshToken(user.getUsername());

        log.info("Login successful for user: {}", user.getUsername());

        AuthResponseDTO response = AuthResponseDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .build();

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDTO> refreshToken(@Valid @RequestBody RefreshTokenRequestDTO request) {
        log.info("Token refresh request");

        try {
            // USAR MÉTODO QUE EXISTE EN TU RefreshTokenService
            String username = refreshTokenService.getUsernameFromToken(request.getRefreshToken());

            // USAR MÉTODO QUE EXISTE EN TU RefreshTokenService
            if (!refreshTokenService.validateToken(request.getRefreshToken())) {
                log.warn("Invalid refresh token");
                throw new BadRequestException("Refresh token inválido");
            }

            // SEGURIDAD: Invalidar el refresh token usado (rotación)
            refreshTokenService.removeToken(request.getRefreshToken());

            // Generar nuevos tokens
            String newAccessToken = refreshTokenService.generateAccessToken(username);
            String newRefreshToken = refreshTokenService.generateRefreshToken(username);

            log.info("Tokens refreshed successfully for user: {}", username);

            AuthResponseDTO response = AuthResponseDTO.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .username(username)
                    .build();

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error refreshing token: {}", e.getMessage());
            throw new BadRequestException("Error al renovar token");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequestDTO request) {
        log.info("Logout request");

        try {
            String username = refreshTokenService.getUsernameFromToken(request.getRefreshToken());

            // SEGURIDAD: Invalidar el refresh token
            refreshTokenService.removeToken(request.getRefreshToken());

            log.info("Logout successful for user: {}", username);
        } catch (Exception e) {
            log.warn("Error during logout: {}", e.getMessage());
        }

        return ResponseEntity.ok().build();
    }
}