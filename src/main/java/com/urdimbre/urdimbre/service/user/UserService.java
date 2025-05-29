package com.urdimbre.urdimbre.service.user;

import java.util.List;
import java.util.Set;

import com.urdimbre.urdimbre.dto.user.UserRequestDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.model.User;

public interface UserService {

    UserResponseDTO getUserByUsername(String username);

    User findByUsername(String username);

    UserResponseDTO registerUser(UserRequestDTO userDTO, Set<String> roles);

    UserResponseDTO updateUser(Long id, UserRequestDTO userDTO);

    UserResponseDTO getUser(Long id);

    List<UserResponseDTO> getAllUsers();

    void deleteUser(Long id);

    UserResponseDTO changePassword(Long id, String currentPassword, String newPassword);
}