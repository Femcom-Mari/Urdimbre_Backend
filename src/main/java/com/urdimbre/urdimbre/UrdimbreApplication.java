package com.urdimbre.urdimbre;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.github.cdimascio.dotenv.Dotenv;

@SpringBootApplication
public class UrdimbreApplication {

	private static final Logger logger = LoggerFactory.getLogger(UrdimbreApplication.class);

	public static void main(String[] args) {
		logger.info("🚀 Iniciando aplicación Urdimbre...");

		try {
			// ✅ CARGAR .env ANTES QUE NADA
			loadEnvironmentVariables();

			SpringApplication.run(UrdimbreApplication.class, args);

			logger.info("✅ Aplicación Urdimbre iniciada correctamente");

		} catch (Exception e) {
			logger.error("❌ Error iniciando aplicación: {}", e.getMessage());
			System.exit(1);
		}
	}

	private static void loadEnvironmentVariables() {
		logger.info("🔧 Cargando variables de entorno...");

		Dotenv dotenv = Dotenv.configure()
				.ignoreIfMissing()
				.load();

		// ✅ ESTABLECER PERFIL ACTIVO ANTES QUE NADA
		setupSpringProfile(dotenv);

		// ✅ CARGAR RATE LIMITING PERMISIVO
		setupRateLimiting(dotenv);

		validateDatabaseConfig(dotenv);
		validateSecurityConfig(dotenv);
		validateAdminConfig(dotenv);

		logger.info("✅ Variables de entorno cargadas y validadas correctamente");
	}

	// ✅ NUEVO: Configurar perfil de Spring ANTES de iniciar
	private static void setupSpringProfile(Dotenv dotenv) {
		String profile = getEnvVariable(dotenv, "SPRING_PROFILES_ACTIVE", "dev");
		System.setProperty("spring.profiles.active", profile);
		logger.info("🔧 Spring Profile establecido: {}", profile);
	}

	// Constante para duración por defecto de rate limiting
	private static final String DEFAULT_RATE_LIMIT_DURATION = "PT30S";

	// ✅ NUEVO: Configurar rate limiting permisivo para desarrollo
	private static void setupRateLimiting(Dotenv dotenv) {
		// Rate limiting para registro
		String registerCapacity = getEnvVariable(dotenv, "RATE_LIMIT_REGISTER_IP_CAPACITY", "100");
		String registerDuration = getEnvVariable(dotenv, "RATE_LIMIT_REGISTER_IP_DURATION",
				DEFAULT_RATE_LIMIT_DURATION);

		// Rate limiting para login por IP
		String loginIpCapacity = getEnvVariable(dotenv, "RATE_LIMIT_LOGIN_IP_CAPACITY", "100");
		String loginIpDuration = getEnvVariable(dotenv, "RATE_LIMIT_LOGIN_IP_DURATION", DEFAULT_RATE_LIMIT_DURATION);

		// Rate limiting para login por usuario
		String loginUserCapacity = getEnvVariable(dotenv, "RATE_LIMIT_LOGIN_USER_CAPACITY", "50");
		String loginUserDuration = getEnvVariable(dotenv, "RATE_LIMIT_LOGIN_USER_DURATION",
				DEFAULT_RATE_LIMIT_DURATION);

		// ✅ ESTABLECER SYSTEM PROPERTIES PARA QUE SPRING LOS USE
		System.setProperty("rate-limit.register.ip.capacity", registerCapacity);
		System.setProperty("rate-limit.register.ip.refill-duration", registerDuration);
		System.setProperty("rate-limit.login.ip.capacity", loginIpCapacity);
		System.setProperty("rate-limit.login.ip.refill-duration", loginIpDuration);
		System.setProperty("rate-limit.login.user.capacity", loginUserCapacity);
		System.setProperty("rate-limit.login.user.refill-duration", loginUserDuration);

		logger.info("🎛️ Rate Limiting configurado:");
		logger.info("   📝 Registro: {} intentos cada {}", registerCapacity, registerDuration);
		logger.info("   🔑 Login IP: {} intentos cada {}", loginIpCapacity, loginIpDuration);
		logger.info("   👤 Login User: {} intentos cada {}", loginUserCapacity, loginUserDuration);
	}

	private static void validateDatabaseConfig(Dotenv dotenv) {
		String dbUrl = getEnvVariable(dotenv, "DB_URL");
		String dbUser = getEnvVariable(dotenv, "DB_USERNAME");
		String dbPass = getEnvVariable(dotenv, "DB_PASSWORD");

		if (dbUrl == null || dbUser == null) {
			logger.error("❌ ERROR: Faltan variables de entorno para la base de datos");
			logger.error("Variables requeridas: DB_URL, DB_USERNAME, DB_PASSWORD");
			throw new IllegalStateException("Configuración de base de datos incompleta");
		}

		if (!dbUrl.startsWith("jdbc:")) {
			logger.error("❌ ERROR: DB_URL debe comenzar con 'jdbc:'");
			throw new IllegalStateException("Formato de DB_URL inválido");
		}

		System.setProperty("spring.datasource.url", dbUrl);
		System.setProperty("spring.datasource.username", dbUser);
		if (dbPass != null) {
			System.setProperty("spring.datasource.password", dbPass);
		}

		logger.info("✅ Configuración de base de datos validada");
		if (logger.isInfoEnabled()) {
			logger.info("🗃️ Base de datos: {}", maskUrl(dbUrl));
		}
	}

	private static void validateSecurityConfig(Dotenv dotenv) {
		String jwtSecret = getEnvVariable(dotenv, "JWT_SECRET_KEY");

		if (jwtSecret == null || jwtSecret.trim().isEmpty()) {
			logger.error("❌ ERROR: JWT_SECRET_KEY no está configurado");
			logger.error("Genera uno con: openssl rand -hex 64");
			throw new IllegalStateException("JWT_SECRET_KEY no configurado");
		}

		if (jwtSecret.length() < 64) {
			logger.error("❌ ERROR: JWT_SECRET_KEY debe tener al menos 64 caracteres");
			logger.error("Actual: {} caracteres", jwtSecret.length());
			logger.error("Genera uno nuevo con: openssl rand -hex 64");
			throw new IllegalStateException("JWT_SECRET_KEY demasiado corto");
		}

		if (!jwtSecret.matches("^[0-9a-fA-F]+$")) {
			logger.warn("⚠️ JWT_SECRET_KEY no parece ser hexadecimal puro");
		}

		System.setProperty("jwt.secret", jwtSecret);

		String accessExp = getEnvVariable(dotenv, "JWT_ACCESS_EXPIRATION", "900000");
		String refreshExp = getEnvVariable(dotenv, "JWT_REFRESH_EXPIRATION", "86400000");

		System.setProperty("jwt.access-token-expiration", accessExp);
		System.setProperty("jwt.refresh-token-expiration", refreshExp);

		logger.info("✅ Configuración de seguridad validada");
		logger.info("🔐 JWT Secret length: {} caracteres", jwtSecret.length());
		logger.info("⏰ Access token expiration: {} ms", accessExp);
		logger.info("⏰ Refresh token expiration: {} ms", refreshExp);
	}

	private static void validateAdminConfig(Dotenv dotenv) {
		String adminUsername = getEnvVariable(dotenv, "ADMIN_USERNAME", "admin");
		String adminEmail = getEnvVariable(dotenv, "ADMIN_EMAIL");
		String adminPassword = getEnvVariable(dotenv, "ADMIN_PASSWORD");

		if (adminEmail == null || adminPassword == null) {
			logger.warn("⚠️ ADMIN_EMAIL o ADMIN_PASSWORD no configurados");
			logger.warn("Se usarán valores por defecto (NO RECOMENDADO PARA PRODUCCIÓN)");
		}

		if (adminPassword != null && !isPasswordSecure(adminPassword)) {
			logger.error("❌ ERROR: ADMIN_PASSWORD no es suficientemente segura");
			logger.error("Debe tener al menos 8 caracteres, mayúscula, minúscula, número y símbolo");
			throw new IllegalStateException("ADMIN_PASSWORD no es segura");
		}

		System.setProperty("admin.username", adminUsername);
		if (adminEmail != null)
			System.setProperty("admin.email", adminEmail);
		if (adminPassword != null)
			System.setProperty("admin.password", adminPassword);

		String inviteCode = getEnvVariable(dotenv, "INVITE_CODE", "URDIMBRE2025");
		System.setProperty("invite.code.default", inviteCode);

		logger.info("✅ Configuración de administrador validada");
		logger.info("👑 Admin username: {}", adminUsername);
		if (adminEmail != null) {
			if (logger.isInfoEnabled()) {
				logger.info("📧 Admin email: {}", maskEmail(adminEmail));
			}
		} else {
			logger.info("📧 Admin email: null");
		}
	}

	private static String getEnvVariable(Dotenv dotenv, String key) {
		return getEnvVariable(dotenv, key, null);
	}

	private static String getEnvVariable(Dotenv dotenv, String key, String defaultValue) {
		// Prioridad: System properties > Environment variables > .env file > default
		String value = System.getProperty(key);
		if (value == null) {
			value = System.getenv(key);
		}
		if (value == null && dotenv != null) {
			value = dotenv.get(key);
		}
		return value != null ? value : defaultValue;
	}

	private static boolean isPasswordSecure(String password) {
		if (password == null || password.length() < 8) {
			return false;
		}

		boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
		boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
		boolean hasDigit = password.chars().anyMatch(Character::isDigit);
		boolean hasSymbol = password.chars().anyMatch(ch -> "@$!%*?&".indexOf(ch) >= 0);

		return hasLower && hasUpper && hasDigit && hasSymbol;
	}

	private static String maskUrl(String url) {
		if (url == null)
			return "null";
		return url.replaceAll("://([^:]+):([^@]+)@", "://*****:*****@");
	}

	private static String maskEmail(String email) {
		if (email == null)
			return "null";
		if (!email.contains("@"))
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