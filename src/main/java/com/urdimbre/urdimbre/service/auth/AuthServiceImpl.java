package com.urdimbre.urdimbre.service.auth;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.urdimbre.urdimbre.dto.auth.AuthRequestDTO;
import com.urdimbre.urdimbre.dto.auth.AuthResponseDTO;
import com.urdimbre.urdimbre.dto.user.UserRegisterDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.exception.BadRequestException;
import com.urdimbre.urdimbre.model.Role;
import com.urdimbre.urdimbre.model.User;
import com.urdimbre.urdimbre.repository.RoleRepository;
import com.urdimbre.urdimbre.repository.UserRepository;
import com.urdimbre.urdimbre.service.invite.InviteCodeService;
import com.urdimbre.urdimbre.service.token.RefreshTokenService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final InviteCodeService inviteCodeService;

    @Override
    @Transactional
    public UserResponseDTO register(UserRegisterDTO dto) {
        logger.info("Registrando usuario: {}", dto.getUsername());

        if (!inviteCodeService.validateInviteCode(dto.getInviteCode())) {
            throw new BadRequestException("Código de invitación inválido o expirado");
        }

        if (userRepository.findByUsername(dto.getUsername()).isPresent()) {
            throw new BadRequestException("El nombre de usuario ya está en uso");
        }
        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            throw new BadRequestException("El correo electrónico ya está registrado");
        }

        User.UserBuilder userBuilder = User.builder()
                .username(dto.getUsername())
                .email(dto.getEmail())
                .password(passwordEncoder.encode(dto.getPassword()))
                .fullName(dto.getFullName())
                .status(User.UserStatus.ACTIVE)
                .biography("Nuevo usuario registrado");

        Set<User.Pronoun> pronounSet = validateAndMapPronouns(dto.getPronouns());
        userBuilder.pronouns(pronounSet);

        User user = userBuilder.build();

        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new BadRequestException("El rol ROLE_USER no existe"));
        user.getRoles().add(userRole);

        User savedUser = userRepository.save(user);

        try {
            inviteCodeService.useInviteCode(dto.getInviteCode(), savedUser.getUsername());
            logger.info("Código de invitación {} usado por {}", dto.getInviteCode(), savedUser.getUsername());
        } catch (Exception e) {
            logger.warn("Error al marcar código como usado: {}", e.getMessage());

        }

        UserResponseDTO response = new UserResponseDTO();
        response.setId(savedUser.getId());
        response.setUsername(savedUser.getUsername());
        response.setEmail(savedUser.getEmail());
        response.setFullName(savedUser.getFullName());
        response.setBiography(savedUser.getBiography());
        response.setLocation(savedUser.getLocation());
        response.setProfileImageUrl(savedUser.getProfileImageUrl());

        if (savedUser.getPronouns() != null && !savedUser.getPronouns().isEmpty()) {
            Set<String> pronounStrings = savedUser.getPronouns().stream()
                    .map(User.Pronoun::getDisplayValue)
                    .collect(Collectors.toSet());
            response.setPronouns(pronounStrings);
        }

        response.setStatus(savedUser.getStatus() != null ? savedUser.getStatus().name() : null);

        response.setCreatedAt(savedUser.getCreatedAt() != null ? savedUser.getCreatedAt().toString() : null);
        response.setUpdatedAt(savedUser.getUpdatedAt() != null ? savedUser.getUpdatedAt().toString() : null);
        response.setCreatedBy(savedUser.getCreatedBy());
        response.setLastModifiedBy(savedUser.getLastModifiedBy());

        response.setRoles(savedUser.getRoles() != null && !savedUser.getRoles().isEmpty()
                ? savedUser.getRoles().stream().map(Role::getName).toList()
                : null);

        logger.info("Usuario registrado exitosamente: {}", savedUser.getUsername());
        return response;
    }

    private Set<User.Pronoun> validateAndMapPronouns(Set<String> pronouns) {
        if (pronouns == null || pronouns.isEmpty()) {
            throw new BadRequestException("Debe seleccionar al menos un pronombre");
        }
        Set<User.Pronoun> pronounSet = new HashSet<>();
        for (String pronounString : pronouns) {
            try {
                User.Pronoun pronoun = User.Pronoun.fromDisplayValue(pronounString);
                pronounSet.add(pronoun);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Pronombre inválido: " + pronounString +
                        ". Valores válidos: Elle, Ella, El");
            }
        }
        return pronounSet;
    }

    @Override
    public AuthResponseDTO login(AuthRequestDTO dto) {
        logger.info("Iniciando login para: {}", dto.getUsername());

        if (dto.getUsername() == null || dto.getUsername().trim().isEmpty()) {
            logger.warn("Username/email vacío en login");
            throw new BadCredentialsException("Username o email es requerido");
        }

        if (dto.getPassword() == null || dto.getPassword().trim().isEmpty()) {
            logger.warn("Password vacía en login para usuario: {}", dto.getUsername());
            throw new BadCredentialsException("Contraseña es requerida");
        }

        Optional<User> optionalUser = userRepository.findByUsername(dto.getUsername());
        logger.debug("Usuario encontrado por username: {}", optionalUser.isPresent());

        if (optionalUser.isEmpty() && dto.getUsername().contains("@")) {
            optionalUser = userRepository.findByEmail(dto.getUsername());
            logger.debug("Usuario encontrado por email: {}", optionalUser.isPresent());
        }

        if (optionalUser.isEmpty()) {
            logger.warn("Usuario no encontrado: {}", dto.getUsername());
            throw new BadCredentialsException("Credenciales inválidas");
        }

        User user = optionalUser.get();

        boolean passwordMatches = passwordEncoder.matches(dto.getPassword(), user.getPassword());
        logger.debug("Password matches para usuario {}: {}", dto.getUsername(), passwordMatches);

        if (!passwordMatches) {
            logger.warn("Contraseña incorrecta para usuario: {}", dto.getUsername());
            throw new BadCredentialsException("Credenciales inválidas");
        }

        if (user.getStatus() != User.UserStatus.ACTIVE) {
            logger.warn("Usuario {} no está activo. Estado: {}", dto.getUsername(), user.getStatus());
            throw new BadCredentialsException("Usuario inactivo");
        }

        logger.info("Generando tokens para usuario: {}", user.getUsername());
        String accessToken = refreshTokenService.generateAccessToken(user.getUsername());
        String refreshToken = refreshTokenService.generateRefreshToken(user.getUsername());

        logger.info("Login exitoso para usuario: {}", user.getUsername());

        return AuthResponseDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .build();
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = refreshTokenService.extractRefreshTokenFromRequest(request);
        if (refreshToken != null) {
            refreshTokenService.removeToken(refreshToken);
            logger.info("Sesión cerrada exitosamente");
        }
    }

    @Override
    public AuthResponseDTO refreshToken(String refreshToken) {
        String username = refreshTokenService.getUsernameFromToken(refreshToken);

        if (username == null) {
            throw new BadCredentialsException("Refresh token inválido o expirado");
        }

        Optional<User> optionalUser = userRepository.findByUsername(username);
        if (optionalUser.isEmpty()) {
            refreshTokenService.removeToken(refreshToken);
            throw new BadCredentialsException("Usuario no encontrado");
        }

        String newAccessToken = refreshTokenService.generateAccessToken(username);
        refreshTokenService.removeToken(refreshToken);
        String newRefreshToken = refreshTokenService.generateRefreshToken(username);

        return AuthResponseDTO.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .username(username)
                .build();
    }
}