package com.urdimbre.urdimbre.service.user;

import java.util.List;
import java.util.Set;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.urdimbre.urdimbre.dto.user.UserRegisterDTO;
import com.urdimbre.urdimbre.dto.user.UserRequestDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.model.User;

public interface UserService {

    // ================================
    // 🔐 MÉTODOS DE REGISTRO Y AUTENTICACIÓN
    // ================================

    UserResponseDTO registerUserFromRegisterDTO(UserRegisterDTO userDTO, Set<String> roles);

    UserResponseDTO registerUser(UserRequestDTO userDTO, Set<String> roles);

    // ================================
    // 👤 MÉTODOS DE CONSULTA DE USUARIOS
    // ================================

    UserResponseDTO getUser(Long id);

    UserResponseDTO getUserByUsername(String username);

    User findByUsername(String username);

    User findByUsernameEntity(String username);

    List<UserResponseDTO> getAllUsers();

    List<UserResponseDTO> getUsersByRole(String role);

    List<UserResponseDTO> getActiveUsersByRole(String role);

    List<UserResponseDTO> getUsersByStatus(User.UserStatus status);

    // ================================
    // 📊 MÉTODOS DE CONSULTA CON PAGINACIÓN
    // ================================

    Page<UserResponseDTO> getAllUsersPaginated(Pageable pageable);

    Page<UserResponseDTO> getUsersByRolePaginated(String role, Pageable pageable);

    // ================================
    // 🔍 MÉTODOS DE BÚSQUEDA Y FILTRADO
    // ================================

    List<UserResponseDTO> searchUsers(String searchText);

    List<UserResponseDTO> searchByUsername(String username);

    List<UserResponseDTO> searchByEmail(String email);

    // ================================
    // ✏️ MÉTODOS DE ACTUALIZACIÓN
    // ================================

    UserResponseDTO updateUser(Long id, UserRequestDTO userDTO);

    UserResponseDTO updateUserRoles(Long id, Set<String> roles);

    UserResponseDTO changePassword(Long id, String currentPassword, String newPassword);

    UserResponseDTO updateUserStatus(Long id, User.UserStatus status);

    UserResponseDTO activateUser(Long id);

    UserResponseDTO deactivateUser(Long id);

    // ================================
    // 🎭 MÉTODOS ESPECÍFICOS DE ROLES
    // ================================

    UserResponseDTO addRoleToUser(Long id, String role);

    UserResponseDTO removeRoleFromUser(Long id, String role);

    boolean userHasRole(Long id, String role);

    // ================================
    // 🗑️ MÉTODOS DE ELIMINACIÓN
    // ================================

    void deleteUser(Long id);

    UserResponseDTO softDeleteUser(Long id);

    // ================================
    // 📈 MÉTODOS DE ESTADÍSTICAS
    // ================================

    long getTotalUsersCount();

    long getUsersCountByRole(String role);

    long getUsersCountByStatus(User.UserStatus status);

    long getActiveUsersCountByRole(String role);

    // ================================
    // ✅ MÉTODOS DE VALIDACIÓN
    // ================================

    boolean isUsernameAvailable(String username);

    boolean isEmailAvailable(String email);

    boolean isUsernameAvailableForUpdate(String username, Long userId);

    boolean isEmailAvailableForUpdate(String email, Long userId);
}