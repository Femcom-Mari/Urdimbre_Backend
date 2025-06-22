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
    private static final String ROLE_ORGANIZER = "ROLE_ORGANIZER";
    private static final String ROLE_USER = "ROLE_USER";
    private static final String ROLE_NOT_FOUND_ERROR = "❌ Rol {} no encontrado en la base de datos";

    @Value("${admin.username}")
    private String adminUsername;

    @Value("${admin.email}")
    private String adminEmail;

    @Value("${admin.password}")
    private String adminPassword;

    @Value("${spring.profiles.active:dev}")
    private String activeProfile;

    private final PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner initData(
            RoleRepository roleRepository,
            UserRepository userRepository) {
        return args -> {
            logger.info("🚀 Inicializando datos del sistema (Perfil: {})...", activeProfile);

            validateSecurityRequirements();

            if (isDevelopmentEnvironment()) {
                debugPasswordConfiguration();
            }

            initRoles(roleRepository);
            initAdminUser(userRepository, roleRepository);
            showInitializationStats(roleRepository, userRepository);

            showSecurityWarnings();
        };
    }

    private void validateSecurityRequirements() {
        logger.info("🔍 Ejecutando validaciones de seguridad...");

        if (adminUsername == null || adminUsername.trim().isEmpty()) {
            throw new IllegalStateException("❌ ADMIN_USERNAME no puede estar vacío");
        }

        if (adminEmail == null || adminEmail.trim().isEmpty()) {
            throw new IllegalStateException("❌ ADMIN_EMAIL no puede estar vacío");
        }

        if (!isValidEmail(adminEmail)) {
            throw new IllegalStateException("❌ ADMIN_EMAIL tiene formato inválido: " + adminEmail);
        }

        if (adminPassword == null || !isPasswordSecure(adminPassword)) {
            throw new IllegalStateException(
                    "❌ ADMIN_PASSWORD debe tener al menos 8 caracteres, mayúscula, minúscula, número y símbolo especial (@$!%*?&). "
                            +
                            "Actual: " + (adminPassword != null ? adminPassword.length() + " caracteres" : "null"));
        }

        if (isProductionEnvironment()) {
            validateProductionRequirements();
        }

        logger.info("✅ Todas las validaciones de seguridad pasaron correctamente");
    }

    private void validateProductionRequirements() {
        logger.info("🏭 Aplicando validaciones de PRODUCCIÓN...");

        if ("admin".equals(adminUsername)) {
            throw new IllegalStateException("❌ SEGURIDAD: No usar 'admin' como username en producción");
        }

        if (adminEmail.contains("@urdimbre.com") || adminEmail.contains("@example.com") ||
                adminEmail.contains("@test.com") || adminEmail.contains("@localhost")) {
            throw new IllegalStateException("❌ SEGURIDAD: Usar un email real en producción, no: " + adminEmail);
        }

        if (adminPassword.contains("Admin123") || adminPassword.contains("password") ||
                adminPassword.contains("123456") || adminPassword.toLowerCase().contains("admin")) {
            throw new IllegalStateException("❌ SEGURIDAD: Cambiar contraseña por defecto en producción");
        }

        if (adminPassword.length() < 12) {
            throw new IllegalStateException(
                    "❌ SEGURIDAD: En producción, ADMIN_PASSWORD debe tener al menos 12 caracteres");
        }

        if (!hasAdvancedPasswordSecurity(adminPassword)) {
            throw new IllegalStateException("❌ SEGURIDAD: Contraseña no es suficientemente compleja para producción");
        }

        logger.info("✅ Validaciones de producción completadas");
    }

    private void debugPasswordConfiguration() {

        if (!isDevelopmentEnvironment()) {
            return;
        }

        logger.info("🔍 [DEV] Verificando configuración de contraseña...");
        logger.info("🔍 [DEV] Admin password longitud: {} caracteres",
                adminPassword != null ? adminPassword.length() : 0);

        if (adminPassword != null) {
            String newHash = passwordEncoder.encode(adminPassword);
            boolean hashWorks = passwordEncoder.matches(adminPassword, newHash);
            logger.info("🔍 [DEV] Nuevo hash funciona: {}", hashWorks);
        } else {
            logger.warn("⚠️ [DEV] adminPassword es null!");
        }
    }

    private void initRoles(RoleRepository roleRepository) {
        logger.info("🎭 Inicializando roles del sistema...");

        int initialRoleCount = (int) roleRepository.count();

        createRoleIfNotExists(roleRepository, ROLE_USER,
                "Default role for registered users - Basic access to platform");
        createRoleIfNotExists(roleRepository, ROLE_ORGANIZER,
                "Role for activity organizers - Can create, update and delete activities and attendance");
        createRoleIfNotExists(roleRepository, ROLE_ADMIN,
                "Role for system administrators - Full system access");

        int finalRoleCount = (int) roleRepository.count();
        int rolesCreated = finalRoleCount - initialRoleCount;

        logger.info("✅ Inicialización de roles completada");
        logger.info("📊 Roles totales: {}, Roles creados: {}", finalRoleCount, rolesCreated);
        logger.info("🏗️ Jerarquía de roles: USER < ORGANIZER < ADMIN");
    }

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

    private void initAdminUser(UserRepository userRepository, RoleRepository roleRepository) {
        logger.info("👑 Verificando usuario administrador...");

        var existingUserOpt = userRepository.findByUsername(adminUsername);
        if (existingUserOpt.isPresent()) {
            logger.info("ℹ️ Usuario administrador ya existe (username): {}", adminUsername);

            User existingUser = existingUserOpt.get();
            boolean currentPasswordMatches = passwordEncoder.matches(adminPassword, existingUser.getPassword());

            if (!currentPasswordMatches) {
                logger.warn("⚠️ ACTUALIZANDO contraseña del usuario admin existente");
                String newHashedPassword = passwordEncoder.encode(adminPassword);
                existingUser.setPassword(newHashedPassword);
                userRepository.save(existingUser);
                logger.info("✅ Contraseña del usuario admin actualizada");

                if (isDevelopmentEnvironment()) {
                    boolean updatedPasswordWorks = passwordEncoder.matches(adminPassword, newHashedPassword);
                    logger.info("🔍 [DEV] Nueva contraseña funciona: {}", updatedPasswordWorks);
                }
            } else {
                logger.info("✅ Contraseña del usuario admin ya está actualizada");
            }

            return;
        }

        if (userRepository.findByEmail(adminEmail).isPresent()) {
            if (logger.isWarnEnabled()) {
                logger.warn("⚠️ Email de administrador ya está en uso: {}", maskEmail(adminEmail));
            }
            return;
        }

        logger.info("🏗️ Creando usuario administrador: {}", adminUsername);

        String hashedPassword = passwordEncoder.encode(adminPassword);

        if (isDevelopmentEnvironment()) {
            boolean hashWorks = passwordEncoder.matches(adminPassword, hashedPassword);
            logger.info("🔍 [DEV] Hash funciona correctamente: {}", hashWorks);
        }

        Set<User.Pronoun> adminPronouns = new HashSet<>();
        adminPronouns.add(User.Pronoun.EL);
        adminPronouns.add(User.Pronoun.ELLE);
        adminPronouns.add(User.Pronoun.ELLA);

        User admin = User.builder()
                .username(adminUsername)
                .email(adminEmail)
                .password(hashedPassword)
                .fullName("System Administrator")
                .biography("Administrator user created automatically by the system")
                .location("System")
                .pronouns(adminPronouns)
                .status(UserStatus.ACTIVE)
                .roles(new HashSet<>())
                .build();

        assignRolesToAdmin(admin, roleRepository);
        User savedAdmin = userRepository.save(admin);
        logAdminCreationResults(savedAdmin);
    }

    private void assignRolesToAdmin(User admin, RoleRepository roleRepository) {
        int rolesAssigned = 0;

        roleRepository.findByName(ROLE_ADMIN).ifPresentOrElse(
                adminRole -> {
                    admin.getRoles().add(adminRole);
                    logger.info("✅ Rol ADMIN asignado al usuario administrador");
                },
                () -> logger.error(ROLE_NOT_FOUND_ERROR, ROLE_ADMIN));

        roleRepository.findByName(ROLE_ORGANIZER).ifPresentOrElse(
                organizerRole -> {
                    admin.getRoles().add(organizerRole);
                    logger.info("✅ Rol ORGANIZER asignado al usuario administrador");
                },
                () -> logger.error(ROLE_NOT_FOUND_ERROR, ROLE_ORGANIZER));

        roleRepository.findByName(ROLE_USER).ifPresentOrElse(
                userRole -> {
                    admin.getRoles().add(userRole);
                    logger.info("✅ Rol USER asignado al usuario administrador");
                },
                () -> logger.error(ROLE_NOT_FOUND_ERROR, ROLE_USER));

        rolesAssigned = admin.getRoles().size();
        logger.info("📊 Total de roles asignados: {}", rolesAssigned);
    }

    private void logAdminCreationResults(User savedAdmin) {
        logger.info("✅ Usuario administrador creado exitosamente");
        logger.info("👤 Username: {}", savedAdmin.getUsername());
        String emailToLog = savedAdmin.getEmail() != null ? maskEmail(savedAdmin.getEmail()) : "null";
        logger.info("📧 Email: {}", emailToLog);
        logger.info("🎭 Roles asignados: {} (USER, ORGANIZER, ADMIN)", savedAdmin.getRoles().size());
        logger.info("🏷️ Pronombres: {} (EL, ELLE, ELLA)", savedAdmin.getPronouns().size());
        logger.info("🎫 Los códigos de invitación serán creados por el administrador cuando sean necesarios");
    }

    private void showInitializationStats(RoleRepository roleRepository, UserRepository userRepository) {
        long totalRoles = roleRepository.count();
        long totalUsers = userRepository.count();
        long adminUsers = userRepository.countByRoles_Name(ROLE_ADMIN);
        long organizerUsers = userRepository.countByRoles_Name(ROLE_ORGANIZER);

        logger.info("📊 ESTADÍSTICAS DE INICIALIZACIÓN:");
        logger.info("   🎭 Total roles: {}", totalRoles);
        logger.info("   👥 Total usuarios: {}", totalUsers);
        logger.info("   👑 Administradores: {}", adminUsers);
        logger.info("   🏗️ Organizadores: {}", organizerUsers);
        logger.info("   🎫 Códigos de invitación: Solo los creados por admin");
        logger.info("🚀 Sistema inicializado correctamente para el perfil: {}", activeProfile);
    }

    private void showSecurityWarnings() {
        if (isDevelopmentEnvironment()) {
            logger.warn("🔐 RECORDATORIO: Cambiar credenciales antes de PRODUCCIÓN!");
            logger.warn("🔐 RECORDATORIO: Configurar HTTPS en producción");
            logger.warn("🔐 RECORDATORIO: Configurar dominios reales en CORS");
            logger.info(
                    "🎫 IMPORTANTE: No hay código de invitación por defecto - el admin debe crear códigos cuando sean necesarios");
        }

        if (isProductionEnvironment()) {
            logger.info("🔒 PRODUCCIÓN: Configuración de seguridad aplicada");
            logger.info("🔒 PRODUCCIÓN: BCrypt strength aumentado");
            logger.info("🔒 PRODUCCIÓN: CORS restringido a HTTPS");
            logger.info("🎫 PRODUCCIÓN: Códigos de invitación solo creados por admin");
        }
    }

    private boolean isValidEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return false;
        }

        return email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$") &&
                !email.contains("..") &&
                !email.startsWith(".") &&
                !email.endsWith(".") &&
                email.length() <= 100;
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

    private boolean hasAdvancedPasswordSecurity(String password) {
        if (password == null || password.length() < 12) {
            return false;
        }

        boolean hasMultipleSymbols = password.chars().filter(ch -> "@$!%*?&".indexOf(ch) >= 0).count() >= 2;
        boolean hasMultipleDigits = password.chars().filter(Character::isDigit).count() >= 2;
        boolean noRepeatingChars = !password.matches(".*(.)\\1{2,}.*");
        boolean noCommonPatterns = !password.toLowerCase().matches(".*(123|abc|qwe|password|admin).*");

        return hasMultipleSymbols && hasMultipleDigits && noRepeatingChars && noCommonPatterns;
    }

    private boolean isProductionEnvironment() {
        return "prod".equals(activeProfile) ||
                "production".equals(activeProfile) ||
                "prd".equals(activeProfile);
    }

    private boolean isDevelopmentEnvironment() {
        return "dev".equals(activeProfile) ||
                "development".equals(activeProfile) ||
                "local".equals(activeProfile) ||
                "preprod".equals(activeProfile);
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return email;
        }

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