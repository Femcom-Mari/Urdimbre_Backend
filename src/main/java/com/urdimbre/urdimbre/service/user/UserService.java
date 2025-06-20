package com.urdimbre.urdimbre.service.user;

import java.util.List;
import java.util.Set;

import com.urdimbre.urdimbre.dto.user.UserRegisterDTO;
import com.urdimbre.urdimbre.dto.user.UserRequestDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.model.User;

public interface UserService {

    // ✅ Métodos para buscar usuarios
    UserResponseDTO getUserByUsername(String username);

    User findByUsername(String username);

    User findByUsernameEntity(String username);

    UserResponseDTO getUser(Long id);

    List<UserResponseDTO> getAllUsers();

    // ✅ Métodos para crear y registrar usuarios
    UserResponseDTO registerUser(UserRequestDTO userDTO, Set<String> roles);

    UserResponseDTO registerUserFromRegisterDTO(UserRegisterDTO userDTO, Set<String> roles);

    // ✅ Métodos para actualizar usuarios
    UserResponseDTO updateUser(Long id, UserRequestDTO userDTO);

    UserResponseDTO updateUserRoles(Long id, Set<String> roles);

    UserResponseDTO changePassword(Long id, String currentPassword, String newPassword);

    // ✅ Método para eliminar usuarios
    void deleteUser(Long id);
}