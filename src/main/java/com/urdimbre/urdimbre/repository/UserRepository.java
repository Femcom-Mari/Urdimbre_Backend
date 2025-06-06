package com.urdimbre.urdimbre.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.urdimbre.urdimbre.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

        Optional<User> findByUsername(String username);

        Optional<User> findByEmail(String email);

        Optional<User> findByUsernameOrEmail(String username, String email);

        Boolean existsByUsername(String username);

        Boolean existsByEmail(String email);

        List<User> findByStatus(User.UserStatus status);

        long countByStatus(User.UserStatus status);

        boolean existsByEmailAndStatus(String email, User.UserStatus status);

        boolean existsByUsernameAndStatus(String username, User.UserStatus status);

        List<User> findByCreatedAtAfter(LocalDateTime date);

        List<User> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);

        long countByCreatedAtAfter(LocalDateTime date);

        List<User> findByRoles_Name(String roleName);

        Page<User> findByRoles_Name(String roleName, Pageable pageable);

        long countByRoles_Name(String roleName);

        boolean existsByUsernameAndRoles_Name(String username, String roleName);
}