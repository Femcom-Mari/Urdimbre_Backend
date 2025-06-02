package com.urdimbre.urdimbre.config;

import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.urdimbre.urdimbre.model.Role;
import com.urdimbre.urdimbre.model.User;
import com.urdimbre.urdimbre.model.User.UserStatus;
import com.urdimbre.urdimbre.repository.RoleRepository;
import com.urdimbre.urdimbre.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class DataInitializer {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Bean
    public CommandLineRunner initData(
            RoleRepository roleRepository,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder) {
        return args -> {
            initRoles(roleRepository);
            initAdminUser(userRepository, roleRepository, passwordEncoder);
        };
    }

    private void initRoles(RoleRepository roleRepository) {
        logger.info("Initializing roles...");

        createRoleIfNotExists(roleRepository, "ROLE_USER", "Default role for registered users");
        createRoleIfNotExists(roleRepository, "ROLE_ADMIN", "Role for system administrators");

        logger.info("Total roles available: {}", roleRepository.count());
    }

    private void createRoleIfNotExists(RoleRepository roleRepository, String roleName, String description) {
        if (roleRepository.findByName(roleName).isEmpty()) {
            logger.info("Creating role: {}", roleName);
            Role role = new Role();
            role.setName(roleName);
            role.setDescription(description);
            roleRepository.save(role);
            logger.info("Role {} created successfully", roleName);
        } else {
            logger.info("Role {} already exists", roleName);
        }
    }

    private void initAdminUser(UserRepository userRepository, RoleRepository roleRepository,
            PasswordEncoder passwordEncoder) {
        String adminUsername = System.getenv("ADMIN_USERNAME");
        String adminEmail = System.getenv("ADMIN_EMAIL");
        String adminPassword = System.getenv("ADMIN_PASSWORD");

        // Usar valores por defecto si no están configurados (SOLO PARA DESARROLLO)
        if (adminUsername == null)
            adminUsername = "admin";
        if (adminEmail == null)
            adminEmail = "admin@urdimbre.com";
        if (adminPassword == null)
            adminPassword = "Admin123!@#";

        // Validar que el password sea seguro
        if (!isPasswordSecure(adminPassword)) {
            throw new IllegalStateException(
                    "ADMIN_PASSWORD debe tener al menos 8 caracteres, mayúscula, minúscula, número y símbolo");
        }

        if (userRepository.findByUsername(adminUsername).isEmpty()) {
            logger.info("Creating admin user: {}", adminUsername);

            User admin = User.builder()
                    .username(adminUsername)
                    .email(adminEmail)
                    .password(passwordEncoder.encode(adminPassword))
                    .fullName("System Administrator") // USAR fullName que existe
                    .biography("System administrator user created automatically")
                    .location("System")
                    .status(UserStatus.ACTIVE)
                    .roles(new HashSet<>())
                    .build();

            // Asignar roles
            roleRepository.findByName("ROLE_ADMIN").ifPresent(adminRole -> {
                admin.getRoles().add(adminRole);
                logger.info("ADMIN role assigned to administrator user");
            });

            roleRepository.findByName("ROLE_USER").ifPresent(userRole -> {
                admin.getRoles().add(userRole);
                logger.info("USER role assigned to administrator user");
            });

            userRepository.save(admin);
            logger.info("Administrator user created successfully");
            logger.info("Email: {}", adminEmail);
            logger.warn("REMEMBER TO CHANGE DEFAULT PASSWORD IN PRODUCTION!");
        } else {
            logger.info("Administrator user already exists: {}", adminUsername);
        }
    }

    private boolean isPasswordSecure(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSymbol = password.chars().anyMatch(ch -> "@$!%*?&".indexOf(ch) >= 0);

        return hasLower && hasUpper && hasDigit && hasSymbol;
    }
}