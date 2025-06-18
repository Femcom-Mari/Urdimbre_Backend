package com.urdimbre.urdimbre.config;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.urdimbre.urdimbre.model.InviteCode;
import com.urdimbre.urdimbre.model.Role;
import com.urdimbre.urdimbre.model.User;
import com.urdimbre.urdimbre.model.User.UserStatus;
import com.urdimbre.urdimbre.repository.InviteCodeRepository;
import com.urdimbre.urdimbre.repository.RoleRepository;
import com.urdimbre.urdimbre.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class DataInitializer {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);
    private static final String ROLE_ADMIN = "ROLE_ADMIN";
    private static final String ROLE_USER = "ROLE_USER";

    @Value("${admin.username}")
    private String adminUsername;

    @Value("${admin.email}")
    private String adminEmail;

    @Value("${admin.password}")
    private String adminPassword;

    @Value("${spring.profiles.active:dev}")
    private String activeProfile;

    @Value("${invite.code.default:URDIMBRE2025}")
    private String defaultInviteCode;

    private final PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner initData(
            RoleRepository roleRepository,
            UserRepository userRepository,
            InviteCodeRepository inviteCodeRepository) {
        return args -> {
            logger.info("🚀 Inicializando datos del sistema (Perfil: {})...", activeProfile);

            // ✅ VALIDACIONES DE SEGURIDAD PRIMERO
            validateSecurityRequirements();

            // ✅ SOLO DEBUG EN DESARROLLO
            if (isDevelopmentEnvironment()) {
                debugPasswordConfiguration();
            }

            // ✅ INICIALIZACIÓN SEGURA
            initRoles(roleRepository);
            initAdminUser(userRepository, roleRepository);
            initDefaultInviteCode(inviteCodeRepository);
            showInitializationStats(roleRepository, userRepository, inviteCodeRepository);

            // ✅ WARNINGS DE SEGURIDAD
            showSecurityWarnings();
        };
    }

    private void validateSecurityRequirements() {
        logger.info("🔍 Ejecutando validaciones de seguridad...");

        // ✅ Validaciones básicas
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

        // ✅ Validaciones de producción
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

        // ✅ Verificar complejidad adicional para producción
        if (!hasAdvancedPasswordSecurity(adminPassword)) {
            throw new IllegalStateException("❌ SEGURIDAD: Contraseña no es suficientemente compleja para producción");
        }

        logger.info("✅ Validaciones de producción completadas");
    }

    private void debugPasswordConfiguration() {
        // ✅ SOLO EN DESARROLLO - No mostrar contraseñas en producción
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

        createRoleIfNotExists(roleRepository, ROLE_USER, "Default role for registered users");
        createRoleIfNotExists(roleRepository, ROLE_ADMIN, "Role for system administrators");

        int finalRoleCount = (int) roleRepository.count();
        int rolesCreated = finalRoleCount - initialRoleCount;

        logger.info("✅ Inicialización de roles completada");
        logger.info("📊 Roles totales: {}, Roles creados: {}", finalRoleCount, rolesCreated);
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

            // ✅ VERIFICAR Y ACTUALIZAR CONTRASEÑA SI ES NECESARIO
            User existingUser = existingUserOpt.get();
            boolean currentPasswordMatches = passwordEncoder.matches(adminPassword, existingUser.getPassword());

            if (!currentPasswordMatches) {
                logger.warn("⚠️ ACTUALIZANDO contraseña del usuario admin existente");
                String newHashedPassword = passwordEncoder.encode(adminPassword);
                existingUser.setPassword(newHashedPassword);
                userRepository.save(existingUser);
                logger.info("✅ Contraseña del usuario admin actualizada");

                // ✅ Verificar que la actualización funcionó (solo en dev)
                if (isDevelopmentEnvironment()) {
                    boolean updatedPasswordWorks = passwordEncoder.matches(adminPassword, newHashedPassword);
                    logger.info("🔍 [DEV] Nueva contraseña funciona: {}", updatedPasswordWorks);
                }
            } else {
                logger.info("✅ Contraseña del usuario admin ya está actualizada");
            }

            return;
        }

        // ✅ Verificar email duplicado
        if (userRepository.findByEmail(adminEmail).isPresent()) {
            if (logger.isWarnEnabled()) {
                logger.warn("⚠️ Email de administrador ya está en uso: {}", maskEmail(adminEmail));
            }
            return;
        }

        logger.info("🏗️ Creando usuario administrador: {}", adminUsername);

        // ✅ CREAR USUARIO ADMIN SEGURO
        User admin = createSecureAdminUser();

        // ✅ ASIGNAR ROLES
        assignRolesToAdmin(admin, roleRepository);

        // ✅ GUARDAR USER
        User savedAdmin = userRepository.save(admin);

        // ✅ LOG RESULTADOS
        logAdminCreationResults(savedAdmin);
    }

    private User createSecureAdminUser() {
        Set<User.Pronoun> adminPronouns = new HashSet<>();
        adminPronouns.add(User.Pronoun.EL);

        // ✅ ENCRIPTAR CONTRASEÑA SEGURAMENTE
        String hashedPassword = passwordEncoder.encode(adminPassword);

        // ✅ Solo verificar en desarrollo
        if (isDevelopmentEnvironment()) {
            boolean hashWorks = passwordEncoder.matches(adminPassword, hashedPassword);
            logger.info("🔍 [DEV] Hash funciona correctamente: {}", hashWorks);
        }

        return User.builder()
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
    }

    private void assignRolesToAdmin(User admin, RoleRepository roleRepository) {
        roleRepository.findByName(ROLE_ADMIN).ifPresentOrElse(
                adminRole -> {
                    admin.getRoles().add(adminRole);
                    logger.info("✅ Rol ADMIN asignado al usuario administrador");
                },
                () -> {
                    logger.error("❌ CRÍTICO: Rol {} no encontrado en la base de datos", ROLE_ADMIN);
                    throw new IllegalStateException("Rol ADMIN no existe");
                });

        roleRepository.findByName(ROLE_USER).ifPresentOrElse(
                userRole -> {
                    admin.getRoles().add(userRole);
                    logger.info("✅ Rol USER asignado al usuario administrador");
                },
                () -> {
                    logger.error("❌ CRÍTICO: Rol ROLE_USER no encontrado en la base de datos");
                    throw new IllegalStateException("Rol USER no existe");
                });
    }

    private void logAdminCreationResults(User savedAdmin) {
        logger.info("✅ Usuario administrador creado exitosamente");
        logger.info("👤 Username: {}", savedAdmin.getUsername());
        if (logger.isInfoEnabled()) {
            logger.info("📧 Email: {}", maskEmail(savedAdmin.getEmail()));
        }
        logger.info("🎭 Roles asignados: {}", savedAdmin.getRoles().size());
        logger.info("🏷️ Pronombres: {}", savedAdmin.getPronouns().size());
    }

    private void initDefaultInviteCode(InviteCodeRepository inviteCodeRepository) {
        // ✅ SOLO CREAR CÓDIGOS EN DESARROLLO
        if (!isDevelopmentEnvironment()) {
            logger.info("ℹ️ Omitiendo creación de código de invitación por defecto en entorno: {}", activeProfile);
            return;
        }

        logger.info("🎫 Verificando código de invitación por defecto: {}", defaultInviteCode);

        if (inviteCodeRepository.findByCode(defaultInviteCode).isEmpty()) {
            logger.info("🏗️ Creando código de invitación por defecto: {}", defaultInviteCode);

            InviteCode inviteCode = InviteCode.builder()
                    .code(defaultInviteCode)
                    .description("Código de invitación por defecto para desarrollo")
                    .maxUses(1000)
                    .currentUses(0)
                    .status(InviteCode.InviteStatus.ACTIVE)
                    .expiresAt(LocalDateTime.now().plusYears(1))
                    .createdBy("system")
                    .build();

            inviteCodeRepository.save(inviteCode);
            logger.info("✅ Código de invitación '{}' creado exitosamente", defaultInviteCode);
        } else {
            logger.info("ℹ️ Código de invitación '{}' ya existe", defaultInviteCode);
        }
    }

    private void showInitializationStats(RoleRepository roleRepository, UserRepository userRepository,
            InviteCodeRepository inviteCodeRepository) {
        long totalRoles = roleRepository.count();
        long totalUsers = userRepository.count();
        long adminUsers = userRepository.countByRoles_Name(ROLE_ADMIN);
        long totalInviteCodes = inviteCodeRepository.count();

        logger.info("📊 ESTADÍSTICAS DE INICIALIZACIÓN:");
        logger.info("   🎭 Total roles: {}", totalRoles);
        logger.info("   👥 Total usuarios: {}", totalUsers);
        logger.info("   👑 Administradores: {}", adminUsers);
        logger.info("   🎫 Códigos de invitación: {}", totalInviteCodes);
        logger.info("🚀 Sistema inicializado correctamente para el perfil: {}", activeProfile);
    }

    private void showSecurityWarnings() {
        if (isDevelopmentEnvironment()) {
            logger.warn("🔐 RECORDATORIO: Cambiar credenciales antes de PRODUCCIÓN!");
            logger.warn("🔐 RECORDATORIO: Configurar HTTPS en producción");
            logger.warn("🔐 RECORDATORIO: Configurar dominios reales en CORS");
        }

        if (isProductionEnvironment()) {
            logger.info("🔒 PRODUCCIÓN: Configuración de seguridad aplicada");
            logger.info("🔒 PRODUCCIÓN: BCrypt strength aumentado");
            logger.info("🔒 PRODUCCIÓN: CORS restringido a HTTPS");
        }
    }

    // ================================
    // ✅ MÉTODOS DE VALIDACIÓN SEGURA
    // ================================

    private boolean isValidEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return false;
        }

        // ✅ Validación más estricta
        return email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$") &&
                !email.contains("..") && // Evitar puntos consecutivos
                !email.startsWith(".") && // No empezar con punto
                !email.endsWith(".") && // No terminar con punto
                email.length() <= 100; // Límite de longitud
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

        // ✅ Verificaciones adicionales para producción
        boolean hasMultipleSymbols = password.chars().filter(ch -> "@$!%*?&".indexOf(ch) >= 0).count() >= 2;
        boolean hasMultipleDigits = password.chars().filter(Character::isDigit).count() >= 2;
        boolean noRepeatingChars = !password.matches(".*(.)\\1{2,}.*"); // No más de 2 caracteres consecutivos iguales
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
                "local".equals(activeProfile);
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