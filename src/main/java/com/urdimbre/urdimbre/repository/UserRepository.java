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

        Optional<User> findByUsername(String username);

        Optional<User> findByEmail(String email);

        boolean existsByUsername(String username);

        boolean existsByEmail(String email);

        List<User> findByRoles_Name(String roleName);

        Page<User> findByRoles_Name(String roleName, Pageable pageable);

        List<User> findByRoles_NameAndStatus(String roleName, User.UserStatus status);

        Page<User> findByRoles_NameAndStatus(String roleName, User.UserStatus status, Pageable pageable);

        long countByRoles_Name(String roleName);

        long countByRoles_NameAndStatus(String roleName, User.UserStatus status);

        List<User> findByRoles_NameOrderByUsernameAsc(String roleName);

        List<User> findByStatus(User.UserStatus status);

        Page<User> findByStatus(User.UserStatus status, Pageable pageable);

        List<User> findByStatusOrderByCreatedAtDesc(User.UserStatus status);

        List<User> findByUsernameContainingIgnoreCase(String username);

        List<User> findByEmailContainingIgnoreCase(String email);

        List<User> findByUsernameContainingIgnoreCaseOrEmailContainingIgnoreCase(String username, String email);

        Page<User> findByUsernameContainingIgnoreCaseOrEmailContainingIgnoreCase(
                        String username, String email, Pageable pageable);

        List<User> findByStatusAndUsernameContainingIgnoreCaseOrStatusAndEmailContainingIgnoreCase(
                        User.UserStatus status1, String username, User.UserStatus status2, String email);

        Page<User> findByStatusAndUsernameContainingIgnoreCaseOrStatusAndEmailContainingIgnoreCase(
                        User.UserStatus status1, String username, User.UserStatus status2, String email,
                        Pageable pageable);

        List<User> findByUsernameAndIdNot(String username, Long id);

        List<User> findByEmailAndIdNot(String email, Long id);

        boolean existsByUsernameAndIdNot(String username, Long id);

        boolean existsByEmailAndIdNot(String email, Long id);

        List<User> findAllByOrderByUsernameAsc();

        @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = ?1")
        List<User> findUsersByRoleName(String roleName);

        @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = ?1 AND u.status = 'ACTIVE'")
        List<User> findActiveUsersByRoleName(String roleName);

        @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.name = ?1 AND u.status = 'ACTIVE'")
        long countActiveUsersByRoleName(String roleName);

        @Query("SELECT DISTINCT u FROM User u JOIN u.roles r WHERE r.name IN ?1")
        List<User> findUsersByRoleNames(List<String> roleNames);
}