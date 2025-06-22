package com.urdimbre.urdimbre.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.urdimbre.urdimbre.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

        // ================================
        // 🔍 MÉTODOS BÁSICOS DE BÚSQUEDA
        // ================================

        Optional<User> findByUsername(String username);

        Optional<User> findByEmail(String email);

        boolean existsByUsername(String username);

        boolean existsByEmail(String email);

        // ================================
        // 🎭 MÉTODOS JPA DERIVADOS PARA ROLES
        // ================================

        /**
         * Busca usuarios por nombre de rol específico
         */
        List<User> findByRoles_Name(String roleName);

        /**
         * Busca usuarios por rol con paginación
         */
        Page<User> findByRoles_Name(String roleName, Pageable pageable);

        /**
         * Busca usuarios por rol y estado específicos
         */
        List<User> findByRoles_NameAndStatus(String roleName, User.UserStatus status);

        /**
         * Busca usuarios por rol y estado con paginación
         */
        Page<User> findByRoles_NameAndStatus(String roleName, User.UserStatus status, Pageable pageable);

        /**
         * Cuenta usuarios por rol específico
         */
        long countByRoles_Name(String roleName);

        /**
         * Cuenta usuarios por rol y estado específicos
         */
        long countByRoles_NameAndStatus(String roleName, User.UserStatus status);

        /**
         * Busca usuarios por rol ordenados por username
         */
        List<User> findByRoles_NameOrderByUsernameAsc(String roleName);

        // ================================
        // 📊 MÉTODOS POR ESTADO
        // ================================

        /**
         * Busca usuarios por estado
         */
        List<User> findByStatus(User.UserStatus status);

        /**
         * Busca usuarios por estado con paginación
         */
        Page<User> findByStatus(User.UserStatus status, Pageable pageable);

        /**
         * Busca usuarios por estado ordenados por fecha de creación descendente
         */
        List<User> findByStatusOrderByCreatedAtDesc(User.UserStatus status);

        // ================================
        // 🔍 MÉTODOS DE BÚSQUEDA Y FILTRADO
        // ================================

        /**
         * Busca usuarios por username que contenga el texto (ignorando mayúsculas)
         */
        List<User> findByUsernameContainingIgnoreCase(String username);

        /**
         * Busca usuarios por email que contenga el texto (ignorando mayúsculas)
         */
        List<User> findByEmailContainingIgnoreCase(String email);

        /**
         * Busca usuarios por username O email que contengan el texto
         */
        List<User> findByUsernameContainingIgnoreCaseOrEmailContainingIgnoreCase(String username, String email);

        /**
         * Busca usuarios por username O email con paginación
         */
        Page<User> findByUsernameContainingIgnoreCaseOrEmailContainingIgnoreCase(
                        String username, String email, Pageable pageable);

        /**
         * Búsqueda compleja por estado y username/email
         */
        List<User> findByStatusAndUsernameContainingIgnoreCaseOrStatusAndEmailContainingIgnoreCase(
                        User.UserStatus status1, String username, User.UserStatus status2, String email);

        /**
         * Búsqueda compleja con paginación
         */
        Page<User> findByStatusAndUsernameContainingIgnoreCaseOrStatusAndEmailContainingIgnoreCase(
                        User.UserStatus status1, String username, User.UserStatus status2, String email,
                        Pageable pageable);

        // ================================
        // ✅ MÉTODOS DE VALIDACIÓN
        // ================================

        /**
         * Busca usuarios con username específico excluyendo un ID
         */
        List<User> findByUsernameAndIdNot(String username, Long id);

        /**
         * Busca usuarios con email específico excluyendo un ID
         */
        List<User> findByEmailAndIdNot(String email, Long id);

        /**
         * Verifica si existe usuario con username excluyendo un ID
         */
        boolean existsByUsernameAndIdNot(String username, Long id);

        /**
         * Verifica si existe usuario con email excluyendo un ID
         */
        boolean existsByEmailAndIdNot(String email, Long id);

        // ================================
        // 📈 MÉTODOS DE ORDENAMIENTO
        // ================================

        /**
         * Obtiene todos los usuarios ordenados por username ascendente
         */
        List<User> findAllByOrderByUsernameAsc();

        // ================================
        // 🔍 CONSULTAS PERSONALIZADAS (OPCIONAL)
        // ================================

        /**
         * Query personalizada para buscar usuarios por rol
         * (alternativa si findByRoles_Name no funciona)
         */
        @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = ?1")
        List<User> findUsersByRoleName(String roleName);

        /**
         * Query para buscar usuarios activos con rol específico
         */
        @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = ?1 AND u.status = 'ACTIVE'")
        List<User> findActiveUsersByRoleName(String roleName);

        /**
         * Query para contar usuarios activos por rol
         */
        @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.name = ?1 AND u.status = 'ACTIVE'")
        long countActiveUsersByRoleName(String roleName);

        /**
         * Query para buscar usuarios con múltiples roles
         */
        @Query("SELECT DISTINCT u FROM User u JOIN u.roles r WHERE r.name IN ?1")
        List<User> findUsersByRoleNames(List<String> roleNames);
}