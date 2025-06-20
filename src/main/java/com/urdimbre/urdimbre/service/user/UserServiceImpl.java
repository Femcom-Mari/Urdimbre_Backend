package com.urdimbre.urdimbre.service.user;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.dto.user.UserRegisterDTO;
import com.urdimbre.urdimbre.dto.user.UserRequestDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.exception.BadRequestException;
import com.urdimbre.urdimbre.model.InviteCode;
import com.urdimbre.urdimbre.model.Role;
import com.urdimbre.urdimbre.model.User;
import com.urdimbre.urdimbre.repository.InviteCodeRepository;
import com.urdimbre.urdimbre.repository.RoleRepository;
import com.urdimbre.urdimbre.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private static final String USER_NOT_FOUND = "Usuario no encontrado";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final InviteCodeRepository inviteCodeRepository;

    @Override
    public UserResponseDTO registerUserFromRegisterDTO(UserRegisterDTO userDTO, Set<String> roles) {
        log.info("🔐 Iniciando registro de usuario desde UserRegisterDTO: {}", userDTO.getUsername());

        validateUniqueUsernameAndEmail(userDTO.getUsername(), userDTO.getEmail());

        boolean isAdminCreating = isAdminCreating();

        if (!isAdminCreating) {
            // Para usuarios normales, validar invite code desde UserRegisterDTO
            if (userDTO.getInviteCode() == null || userDTO.getInviteCode().isBlank()) {
                throw new BadRequestException("Se requiere un código de invitación para registrarse");
            }
            validateAndUseInviteCodeFromRegisterDTO(userDTO);
        } else {
            log.info("🔑 ADMIN creando usuario sin código de invitación: {}", userDTO.getUsername());
        }

        User user = convertFromRegisterDTOToEntity(userDTO);
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));

        Set<Role> roleSet = assignRoles(roles, isAdminCreating);
        user.setRoles(roleSet);

        User savedUser = userRepository.save(user);

        log.info("✅ Usuario {} creado exitosamente con roles: {}",
                savedUser.getUsername(),
                savedUser.getRoles().stream().map(Role::getName).toList());

        return mapToResponseDTO(savedUser);
    }

    private void validateAndUseInviteCodeFromRegisterDTO(UserRegisterDTO userDTO) {
        log.info("👥 Registro público - validando código de invitación para: {}", userDTO.getUsername());

        InviteCode inviteCode = inviteCodeRepository.findByCode(userDTO.getInviteCode())
                .orElseThrow(() -> new BadRequestException("Código de invitación inválido"));

        if (!inviteCode.isValid()) {
            throw new BadRequestException("Este código de invitación no está activo o ha expirado o ya fue usado");
        }

        inviteCode.incrementUses(userDTO.getUsername());
        inviteCodeRepository.save(inviteCode);
        log.info("✅ Código de invitación validado y usado para: {}", userDTO.getUsername());
    }

    private User convertFromRegisterDTOToEntity(UserRegisterDTO dto) {
        User.UserBuilder userBuilder = User.builder()
                .username(dto.getUsername())
                .email(dto.getEmail())
                .password(dto.getPassword())
                .fullName(dto.getFullName()) // UserRegisterDTO ya tiene getFullName()
                .biography("Nuevo usuario registrado")
                .status(User.UserStatus.ACTIVE);

        if (dto.getPronouns() != null && !dto.getPronouns().isEmpty()) {
            Set<User.Pronoun> pronounSet = new HashSet<>();
            for (String pronounString : dto.getPronouns()) {
                try {
                    User.Pronoun pronoun = User.Pronoun.fromDisplayValue(pronounString);
                    pronounSet.add(pronoun);
                } catch (IllegalArgumentException e) {
                    throw new BadRequestException("Pronombre inválido: " + pronounString);
                }
            }
            userBuilder.pronouns(pronounSet);
        }

        return userBuilder.build();
    }

    @Override
    public User findByUsernameEntity(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new BadRequestException(USER_NOT_FOUND));
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new BadRequestException(USER_NOT_FOUND));
    }

    @Override
    public UserResponseDTO getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BadRequestException(USER_NOT_FOUND));
        return mapToResponseDTO(user);
    }

    private boolean isAdminCreating() {
        return SecurityContextHolder.getContext().getAuthentication() != null &&
                SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                        .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
    }

    private void validateAndUseInviteCode(UserRequestDTO userDTO) {
        log.info("👥 Registro público - validando código de invitación para: {}", userDTO.getUsername());

        if (userDTO.getInviteCode() == null || userDTO.getInviteCode().isBlank()) {
            throw new BadRequestException("Se requiere un código de invitación para registrarse");
        }

        InviteCode inviteCode = inviteCodeRepository.findByCode(userDTO.getInviteCode())
                .orElseThrow(() -> new BadRequestException("Código de invitación inválido"));

        // ✅ Usar el método isValid() que ya existe en el modelo
        if (!inviteCode.isValid()) {
            throw new BadRequestException("Este código de invitación no está activo o ha expirado o ya fue usado");
        }

        inviteCode.incrementUses(userDTO.getUsername());
        inviteCodeRepository.save(inviteCode);
        log.info("✅ Código de invitación validado y usado para: {}", userDTO.getUsername());
    }

    private Set<Role> assignRoles(Set<String> roles, boolean isAdminCreating) {
        Set<Role> roleSet = new HashSet<>();

        // Si no se especifican roles o está vacío, asignar ROLE_USER por defecto
        if (roles == null || roles.isEmpty()) {
            log.info("📝 No se especificaron roles, asignando ROLE_USER por defecto");
            Role userRole = roleRepository.findByName("ROLE_USER")
                    .orElseThrow(() -> new BadRequestException("Rol ROLE_USER no encontrado"));
            roleSet.add(userRole);
        } else {
            // ✅ PROCESAR ROLES ESPECIFICADOS
            log.info("🎭 Procesando roles especificados: {}", roles);

            for (String roleName : roles) {
                Role role = processAndValidateRole(roleName, isAdminCreating);
                roleSet.add(role);
            }
        }
        return roleSet;
    }

    private Role processAndValidateRole(String roleName, boolean isAdminCreating) {
        // Limpiar nombre del rol y asegurar formato correcto
        String cleanRoleNameTemp = roleName.trim().toUpperCase();
        final String cleanRoleName = cleanRoleNameTemp.startsWith("ROLE_")
                ? cleanRoleNameTemp
                : "ROLE_" + cleanRoleNameTemp;

        log.info("🔍 Procesando rol: {} -> {}", roleName, cleanRoleName);

        // ✅ VALIDAR PERMISOS PARA CREAR USUARIOS CON ROLES ESPECÍFICOS
        if ("ROLE_ADMIN".equals(cleanRoleName) && !isAdminCreating) {
            throw new BadRequestException("Solo los administradores pueden crear otros administradores");
        }

        if ("ROLE_ORGANIZER".equals(cleanRoleName) && !isAdminCreating) {
            throw new BadRequestException("Solo los administradores pueden crear organizadores");
        }

        Role role = roleRepository.findByName(cleanRoleName)
                .orElseThrow(() -> new BadRequestException("Rol " + cleanRoleName + " no encontrado"));
        log.info("✅ Rol {} asignado correctamente", cleanRoleName);
        return role;
    }

    @Override
    public UserResponseDTO registerUser(UserRequestDTO userDTO, Set<String> roles) {
        log.info("🔐 Iniciando registro de usuario: {}", userDTO.getUsername());

        validateUniqueUsernameAndEmail(userDTO.getUsername(), userDTO.getEmail());

        boolean isAdminCreating = isAdminCreating();

        if (!isAdminCreating) {
            validateAndUseInviteCode(userDTO);
        } else {
            log.info("🔑 ADMIN creando usuario sin código de invitación: {}", userDTO.getUsername());
        }

        User user = convertToEntity(userDTO);
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));

        Set<Role> roleSet = assignRoles(roles, isAdminCreating);

        user.setRoles(roleSet);
        User savedUser = userRepository.save(user);

        log.info("✅ Usuario {} creado exitosamente con roles: {}",
                savedUser.getUsername(),
                savedUser.getRoles().stream().map(Role::getName).toList());

        return mapToResponseDTO(savedUser);
    }

    @Override
    public UserResponseDTO updateUser(Long id, UserRequestDTO userDTO) {
        log.info("📝 Actualizando usuario ID: {}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new BadRequestException(USER_NOT_FOUND));

        if (userDTO.getEmail() != null)
            user.setEmail(userDTO.getEmail());
        if (userDTO.getFullName() != null)
            user.setFullName(userDTO.getFullName());
        if (userDTO.getBiography() != null)
            user.setBiography(userDTO.getBiography());
        if (userDTO.getLocation() != null)
            user.setLocation(userDTO.getLocation());
        if (userDTO.getProfileImageUrl() != null)
            user.setProfileImageUrl(userDTO.getProfileImageUrl());

        if (userDTO.getPronouns() != null && !userDTO.getPronouns().isEmpty()) {
            Set<User.Pronoun> pronounSet = new HashSet<>();
            for (String pronounString : userDTO.getPronouns()) {
                try {
                    User.Pronoun pronoun = User.Pronoun.fromDisplayValue(pronounString);
                    pronounSet.add(pronoun);
                } catch (IllegalArgumentException e) {
                    throw new BadRequestException("Pronombre inválido: " + pronounString);
                }
            }
            user.setPronouns(pronounSet);
        }

        User updatedUser = userRepository.save(user);
        log.info("✅ Usuario {} actualizado exitosamente", updatedUser.getUsername());

        return mapToResponseDTO(updatedUser);
    }

    @Override
    public UserResponseDTO updateUserRoles(Long id, Set<String> roles) {
        log.info("🎭 Actualizando roles para usuario ID: {}", id);

        // Verificar que solo ADMIN puede cambiar roles
        boolean isAdminUpdating = isAdminCreating();
        if (!isAdminUpdating) {
            throw new BadRequestException("Solo los administradores pueden cambiar roles de usuarios");
        }

        User user = userRepository.findById(id)
                .orElseThrow(() -> new BadRequestException(USER_NOT_FOUND));

        Set<Role> roleSet = assignRoles(roles, true); // true porque es admin
        user.setRoles(roleSet);

        User updatedUser = userRepository.save(user);
        log.info("✅ Roles actualizados para usuario {}: {}",
                updatedUser.getUsername(),
                updatedUser.getRoles().stream().map(Role::getName).toList());

        return mapToResponseDTO(updatedUser);
    }

    @Override
    public UserResponseDTO getUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new BadRequestException(USER_NOT_FOUND));
        return mapToResponseDTO(user);
    }

    @Override
    public List<UserResponseDTO> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::mapToResponseDTO)
                .toList();
    }

    @Override
    public void deleteUser(Long id) {
        log.info("🗑️ Eliminando usuario ID: {}", id);

        if (!userRepository.existsById(id)) {
            throw new BadRequestException(USER_NOT_FOUND);
        }
        userRepository.deleteById(id);

        log.info("✅ Usuario ID {} eliminado exitosamente", id);
    }

    @Override
    public UserResponseDTO changePassword(Long id, String currentPassword, String newPassword) {
        log.info("🔐 Cambiando contraseña para usuario ID: {}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new BadRequestException(USER_NOT_FOUND));

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new BadRequestException("Contraseña actual incorrecta");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        User updatedUser = userRepository.save(user);

        log.info("✅ Contraseña cambiada exitosamente para usuario: {}", updatedUser.getUsername());

        return mapToResponseDTO(updatedUser);
    }

    private void validateUniqueUsernameAndEmail(String username, String email) {
        if (userRepository.existsByUsername(username)) {
            throw new BadRequestException("El nombre de usuario ya está en uso");
        }
        if (userRepository.existsByEmail(email)) {
            throw new BadRequestException("El correo electrónico ya está en uso");
        }
    }

    private User convertToEntity(UserRequestDTO dto) {
        User.UserBuilder userBuilder = User.builder()
                .username(dto.getUsername())
                .email(dto.getEmail())
                .password(dto.getPassword())
                .fullName(dto.getFullName())
                .biography(dto.getBiography() != null ? dto.getBiography() : "Nuevo usuario registrado")
                .location(dto.getLocation())
                .profileImageUrl(dto.getProfileImageUrl())
                .status(User.UserStatus.ACTIVE);

        if (dto.getPronouns() != null && !dto.getPronouns().isEmpty()) {
            Set<User.Pronoun> pronounSet = new HashSet<>();
            for (String pronounString : dto.getPronouns()) {
                try {
                    User.Pronoun pronoun = User.Pronoun.fromDisplayValue(pronounString);
                    pronounSet.add(pronoun);
                } catch (IllegalArgumentException e) {
                    throw new BadRequestException("Pronombre inválido: " + pronounString);
                }
            }
            userBuilder.pronouns(pronounSet);
        }

        return userBuilder.build();
    }

    // ✅ MÉTODO REFACTORIZADO USANDO BUILDER PATTERN
    private UserResponseDTO mapToResponseDTO(User user) {
        UserResponseDTO.UserResponseDTOBuilder builder = UserResponseDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .biography(user.getBiography())
                .location(user.getLocation())
                .profileImageUrl(user.getProfileImageUrl())
                .status(user.getStatus() != null ? user.getStatus().name() : null)
                .createdAt(user.getCreatedAt() != null ? user.getCreatedAt().toString() : null)
                .updatedAt(user.getUpdatedAt() != null ? user.getUpdatedAt().toString() : null)
                .createdBy(user.getCreatedBy())
                .lastModifiedBy(user.getLastModifiedBy());

        // ✅ PROCESAR PRONOMBRES
        if (user.getPronouns() != null && !user.getPronouns().isEmpty()) {
            Set<String> pronounStrings = user.getPronouns().stream()
                    .map(User.Pronoun::getDisplayValue)
                    .collect(Collectors.toSet());
            builder.pronouns(pronounStrings);
        }

        // ✅ PROCESAR ROLES
        if (user.getRoles() != null && !user.getRoles().isEmpty()) {
            List<String> roleNames = user.getRoles().stream()
                    .map(Role::getName)
                    .toList();
            builder.roles(roleNames);
        }

        return builder.build();
    }
}