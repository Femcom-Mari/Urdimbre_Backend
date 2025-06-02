package com.urdimbre.urdimbre.service.user;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.urdimbre.urdimbre.dto.user.UserRequestDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.model.Role;
import com.urdimbre.urdimbre.model.User;
import com.urdimbre.urdimbre.repository.RoleRepository;
import com.urdimbre.urdimbre.repository.UserRepository;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, RoleRepository roleRepository,
            PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserResponseDTO getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
        return mapToResponseDTO(user);
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
    }

    @Override
    public UserResponseDTO registerUser(UserRequestDTO userDTO, Set<String> roles) {
        validateUniqueUsernameAndEmail(userDTO.getUsername(), userDTO.getEmail());

        User user = convertToEntity(userDTO);
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));

        Set<Role> roleSet = roles.stream()
                .map(roleName -> roleRepository.findByName("ROLE_" + roleName)
                        .orElseThrow(() -> new RuntimeException("Rol no encontrado: " + roleName)))
                .collect(Collectors.toSet());

        user.setRoles(roleSet);

        User savedUser = userRepository.save(user);
        return mapToResponseDTO(savedUser);
    }

    @Override
    public UserResponseDTO updateUser(Long id, UserRequestDTO userDTO) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        user.setFirstName(userDTO.getFirstName());
        user.setLastName(userDTO.getLastName());
        user.setEmail(userDTO.getEmail());
        user.setBiography(userDTO.getBiography());
        user.setLocation(userDTO.getLocation());
        user.setProfileImageUrl(userDTO.getProfileImageUrl());
        user.setUserStatus(userDTO.getUserStatus());
        user.setPronouns(userDTO.getPronouns() != null ? User.Pronoun.valueOf(userDTO.getPronouns()) : null);
        user.setInvitationCode(userDTO.getInvitationCode());

        User updatedUser = userRepository.save(user);
        return mapToResponseDTO(updatedUser);
    }

    @Override
    public UserResponseDTO getUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
        return mapToResponseDTO(user);
    }

    @Override
    public List<UserResponseDTO> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::mapToResponseDTO)
                .collect(Collectors.toList());
    }

    @Override
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new RuntimeException("Usuario no encontrado");
        }
        userRepository.deleteById(id);
    }

    @Override
    public UserResponseDTO changePassword(Long id, String currentPassword, String newPassword) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new RuntimeException("Contraseña actual incorrecta");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        User updatedUser = userRepository.save(user);
        return mapToResponseDTO(updatedUser);
    }

    // --- Métodos privados reutilizables ---

    private void validateUniqueUsernameAndEmail(String username, String email) {
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("El nombre de usuario ya está en uso");
        }
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("El correo electrónico ya está en uso");
        }
    }

    private User convertToEntity(UserRequestDTO dto) {
        User user = new User();
        user.setUsername(dto.getUsername());
        user.setEmail(dto.getEmail());
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setPassword(dto.getPassword());
        user.setBiography(dto.getBiography());
        user.setLocation(dto.getLocation());
        user.setProfileImageUrl(dto.getProfileImageUrl());
        user.setUserStatus(dto.getUserStatus());
        user.setPronouns(dto.getPronouns() != null ? User.Pronoun.valueOf(dto.getPronouns()) : null);
        user.setInvitationCode(dto.getInvitationCode());
        return user;
    }

    private UserResponseDTO mapToResponseDTO(User user) {
        String fullName = ((user.getFirstName() != null ? user.getFirstName() : "") +
                (user.getLastName() != null ? " " + user.getLastName() : "")).trim();

        return new UserResponseDTO(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                fullName,
                user.getBiography(),
                user.getLocation(),
                user.getProfileImageUrl(),
                user.getUserStatus(),
                user.getPronouns() != null ? user.getPronouns().name() : null,
                user.getInvitationCode(),
                user.getCreatedAt() != null ? user.getCreatedAt().toString() : null,
                user.getUpdatedAt() != null ? user.getUpdatedAt().toString() : null,
                user.getRoles() != null
                        ? user.getRoles().stream().map(Role::getName).collect(Collectors.toList())
                        : null);
    }
}