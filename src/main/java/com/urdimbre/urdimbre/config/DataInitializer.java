package com.urdimbre.urdimbre.config;

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
    private static final String ROLE_ADMIN = "ROLE_ADMIN";
    private static final String ROLE_USER = "ROLE_USER";

    // 🔐 INYECCIÓN SEGURA DE VARIABLES DE ENTORNO
    @Value("${admin.username}")
    private String adminUsername;

    @Value("${admin.email}")
    private String adminEmail;

    @Value("${admin.password}")
    private String adminPassword;

    // 🌍 DETECTAR ENTORNO
    @Value("${spring.profiles.active:dev}")
    private String activeProfile;

    @Bean
    public CommandLineRunner initData(
            RoleRepository roleRepository,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder) { // ✅ CAMBIADO: usar PasswordEncoder en lugar de BCryptPasswordEncoder
        return args -> {
            logger.info("🚀 Inicializando datos del sistema (Perfil: {})...", activeProfile);

            // 🔐 VALIDACIONES DE SEGURIDAD ESTRICTAS
            validateSecurityRequirements();

            // 🎭 INICIALIZAR ROLES Y USUARIO ADMIN
            initRoles(roleRepository);
            initAdminUser(userRepository, roleRepository, passwordEncoder);

            // 📊 MOSTRAR ESTADÍSTICAS FINALES
            showInitializationStats(roleRepository, userRepository);
        };
    }

    /**
     * 🔐 Validaciones de seguridad estrictas
     */
    private void validateSecurityRequirements() {
        logger.info("🔍 Ejecutando validaciones de seguridad...");

        // ✅ VALIDAR USUARIO ADMINISTRADOR
        if (adminUsername == null || adminUsername.trim().isEmpty()) {
            throw new IllegalStateException("❌ ADMIN_USERNAME no puede estar vacío");
        }

        if (adminEmail == null || adminEmail.trim().isEmpty()) {
            throw new IllegalStateException("❌ ADMIN_EMAIL no puede estar vacío");
        }

        // ✅ VALIDAR EMAIL FORMATO
        if (!isValidEmail(adminEmail)) {
            throw new IllegalStateException("❌ ADMIN_EMAIL tiene formato inválido: " + adminEmail);
        }

        // ✅ VALIDAR CONTRASEÑA SEGURA
        if (adminPassword == null || !isPasswordSecure(adminPassword)) {
            throw new IllegalStateException(
                    "❌ ADMIN_PASSWORD debe tener al menos 8 caracteres, mayúscula, minúscula, número y símbolo especial (@$!%*?&). "
                            + "Actual: " + (adminPassword != null ? adminPassword.length() + " caracteres" : "null"));
        }

        // 🚨 VALIDACIONES ESPECÍFICAS PARA PRODUCCIÓN
        if ("prod".equals(activeProfile) || "production".equals(activeProfile)) {
            validateProductionRequirements();
        }

        logger.info("✅ Todas las validaciones de seguridad pasaron correctamente");
    }

    /**
     * 🏭 Validaciones específicas para producción
     */
    private void validateProductionRequirements() {
        logger.info("🏭 Aplicando validaciones de producción...");

        // ❌ NO PERMITIR CREDENCIALES POR DEFECTO EN PRODUCCIÓN
        if ("admin".equals(adminUsername)) {
            throw new IllegalStateException("❌ No usar 'admin' como username en producción");
        }

        if (adminEmail.contains("@urdimbre.com") || adminEmail.contains("@example.com")) {
            throw new IllegalStateException("❌ Usar un email real en producción, no: " + adminEmail);
        }

        if (adminPassword.contains("Admin123") || adminPassword.contains("password")) {
            throw new IllegalStateException("❌ Cambiar contraseña por defecto en producción");
        }

        // ✅ VALIDAR LONGITUD MÍNIMA EN PRODUCCIÓN
        if (adminPassword.length() < 12) {
            throw new IllegalStateException("❌ En producción, ADMIN_PASSWORD debe tener al menos 12 caracteres");
        }

        logger.info("✅ Validaciones de producción completadas");
    }

    /**
     * 🎭 Inicializar roles del sistema
     */
    private void initRoles(RoleRepository roleRepository) {
        logger.info("🎭 Inicializando roles del sistema...");

        int initialRoleCount = (int) roleRepository.count();

        // 🎯 CREAR ROLES BÁSICOS
        createRoleIfNotExists(roleRepository, ROLE_USER, "Default role for registered users");
        createRoleIfNotExists(roleRepository, ROLE_ADMIN, "Role for system administrators");

        int finalRoleCount = (int) roleRepository.count();
        int rolesCreated = finalRoleCount - initialRoleCount;

        logger.info("✅ Inicialización de roles completada");
        logger.info("📊 Roles totales: {}, Roles creados: {}", finalRoleCount, rolesCreated);
    }

    /**
     * 🏗️ Crear rol si no existe
     */
    private void createRoleIfNotExists(RoleRepository roleRepository, String roleName, String description) {
        if (roleRepository.findByName(roleName).isEmpty()) {
            logger.info("➕ Creando rol: {}", roleName);

            Role role = new Role();
            role.setName(roleName);
            role.setDescription(description);
            roleRepository.save(role);

            logger.info("✅ Rol {} creado exitosamente", roleName);
        } else {
            logger.info("ℹ️ Rol {} ya existe", roleName);
        }
    }

    /**
     * 👑 Inicializar usuario administrador con múltiples pronombres
     */
    private void initAdminUser(UserRepository userRepository, RoleRepository roleRepository,
            PasswordEncoder passwordEncoder) { // ✅ CAMBIADO: usar PasswordEncoder

        logger.info("👑 Verificando usuario administrador...");

        // 🔍 VERIFICAR SI YA EXISTE POR USERNAME O EMAIL
        if (userRepository.findByUsername(adminUsername).isPresent()) {
            logger.info("ℹ️ Usuario administrador ya existe (username): {}", adminUsername);
            return;
        }

        if (userRepository.findByEmail(adminEmail).isPresent()) {
            if (logger.isWarnEnabled()) {
                logger.warn("⚠️ Email de administrador ya está en uso: {}", maskEmail(adminEmail));
            }
            return;
        }

        logger.info("🏗️ Creando usuario administrador: {}", adminUsername);

        // ✅ CREAR SET DE PRONOMBRES PARA ADMIN (ejemplo con múltiples)
        Set<User.Pronoun> adminPronouns = new HashSet<>();
        adminPronouns.add(User.Pronoun.EL); // Pronombre por defecto para admin

        // 🏗️ CREAR USUARIO ADMINISTRADOR CON MÚLTIPLES PRONOMBRES
        User admin = User.builder()
                .username(adminUsername)
                .email(adminEmail)
                .password(passwordEncoder.encode(adminPassword))
                .fullName("System Administrator")
                .biography("Administrator user created automatically by the system")
                .location("System")
                .pronouns(adminPronouns) // ✅ SET DE PRONOMBRES
                .status(UserStatus.ACTIVE)
                .roles(new HashSet<>())
                .build();

        // 🎭 ASIGNAR ROLES AL ADMINISTRADOR
        int rolesAssigned = 0;

        // ROL DE ADMINISTRADOR
        roleRepository.findByName(ROLE_ADMIN).ifPresentOrElse(
                adminRole -> {
                    admin.getRoles().add(adminRole);
                    logger.info("✅ Rol ADMIN asignado al usuario administrador");
                },
                () -> logger.error("❌ Rol {} no encontrado en la base de datos", ROLE_ADMIN));

        // ROL DE USUARIO (para acceso básico)
        roleRepository.findByName(ROLE_USER).ifPresentOrElse(
                userRole -> {
                    admin.getRoles().add(userRole);
                    logger.info("✅ Rol USER asignado al usuario administrador");
                },
                () -> logger.error("❌ Rol ROLE_USER no encontrado en la base de datos"));

        rolesAssigned = admin.getRoles().size();

        // 💾 GUARDAR USUARIO ADMINISTRADOR
        User savedAdmin = userRepository.save(admin);

        logger.info("✅ Usuario administrador creado exitosamente");
        logger.info("👤 Username: {}", savedAdmin.getUsername());
        String emailToLog = savedAdmin.getEmail() != null ? maskEmail(savedAdmin.getEmail()) : "null";
        logger.info("📧 Email: {}", emailToLog);
        logger.info("🎭 Roles asignados: {}", rolesAssigned);
        logger.info("🏷️ Pronombres: {}", savedAdmin.getPronouns().size());

        // 🚨 RECORDATORIO DE SEGURIDAD
        if ("dev".equals(activeProfile)) {
            logger.warn("🔐 RECUERDA CAMBIAR LAS CREDENCIALES POR DEFECTO ANTES DE PRODUCCIÓN!");
        }
    }

    /**
     * 📊 Mostrar estadísticas de inicialización
     */
    private void showInitializationStats(RoleRepository roleRepository, UserRepository userRepository) {
        long totalRoles = roleRepository.count();
        long totalUsers = userRepository.count();
        long adminUsers = userRepository.countByRoles_Name(ROLE_ADMIN);

        logger.info("📊 ESTADÍSTICAS DE INICIALIZACIÓN:");
        logger.info("   🎭 Total roles: {}", totalRoles);
        logger.info("   👥 Total usuarios: {}", totalUsers);
        logger.info("   👑 Administradores: {}", adminUsers);
        logger.info("🚀 Sistema inicializado correctamente para el perfil: {}", activeProfile);
    }

    /**
     * 📧 Validar formato de email
     */
    private boolean isValidEmail(String email) {
        return email != null && email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }

    /**
     * 🔐 Validar que la contraseña sea segura
     */
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

    /**
     * 🎭 Enmascarar email para logs
     */
    private String maskEmail(String email) {
        if (email == null || !email.contains("@"))
            return email;

        String[] parts = email.split("@");
        String localPart = parts[0];
        String domain = parts[1];

        if (localPart.length() <= 2) {
            return "*".repeat(localPart.length()) + "@" + domain;
        } else {
            return localPart.charAt(0) + "*".repeat(localPart.length() - 2) +
                    localPart.charAt(localPart.length() - 1) + "@" + domain;
        }
    }
}