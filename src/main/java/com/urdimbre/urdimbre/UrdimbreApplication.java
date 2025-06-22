package com.urdimbre.urdimbre;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.github.cdimascio.dotenv.Dotenv;

@SpringBootApplication
public class UrdimbreApplication {

	private static final Logger logger = LoggerFactory.getLogger(UrdimbreApplication.class);

	private static final class ConfigDefaults {
		static final String DEFAULT_PROFILE = "preprod";
		static final String DEFAULT_RATE_LIMIT_DURATION = "PT1M";
		static final String DEFAULT_REGISTER_CAPACITY = "10";
		static final String DEFAULT_LOGIN_IP_CAPACITY = "15";
		static final String DEFAULT_LOGIN_USER_CAPACITY = "5";
		static final String DEFAULT_ACCESS_EXPIRATION = "600000";
		static final String DEFAULT_REFRESH_EXPIRATION = "3600000";
		static final int MIN_JWT_SECRET_LENGTH = 64;
		static final int MIN_PASSWORD_LENGTH = 8;
		static final String ENVIRONMENT_KEY = "ENVIRONMENT";
	}

	public static void main(String[] args) {
		logger.info("🚀 Iniciando aplicación Urdimbre en modo preproducción...");
		try {
			loadEnvironmentVariables();
			SpringApplication.run(UrdimbreApplication.class, args);
			logger.info("✅ Aplicación Urdimbre iniciada correctamente");
		} catch (Exception e) {
			logger.error("❌ Error iniciando aplicación: {}", e.getMessage());
			System.exit(1);
		}
	}

	private static void loadEnvironmentVariables() {
		logger.info("🔧 Cargando variables de entorno para preproducción...");
		Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();
		validateEnvironment();
		setupSpringProfile(dotenv);
		setupRateLimiting(dotenv);
		validateDatabaseConfig(dotenv);
		validateSecurityConfig(dotenv);
		validateAdminConfig(dotenv);
		logger.info("✅ Variables de entorno cargadas y validadas correctamente");
	}

	private static void validateEnvironment() {
		String environment = System.getenv(ConfigDefaults.ENVIRONMENT_KEY);
		if (environment == null || !environment.equals(ConfigDefaults.DEFAULT_PROFILE)) {
			logger.warn("⚠️ Variable ENVIRONMENT no está configurada como '{}'", ConfigDefaults.DEFAULT_PROFILE);
		}
	}

	private static void setupSpringProfile(Dotenv dotenv) {
		String profile = getEnvVariable(dotenv, "SPRING_PROFILES_ACTIVE", ConfigDefaults.DEFAULT_PROFILE);
		System.setProperty("spring.profiles.active", profile);
		logger.info("🔧 Spring Profile establecido: {}", profile);
		if (!profile.equals(ConfigDefaults.DEFAULT_PROFILE)) {
			logger.warn("⚠️ Perfil '{}' puede no ser apropiado para preproducción", profile);
		}
	}

	private static void setupRateLimiting(Dotenv dotenv) {
		String registerCapacity = getEnvVariable(dotenv, "RATE_LIMIT_REGISTER_IP_CAPACITY",
				ConfigDefaults.DEFAULT_REGISTER_CAPACITY);
		String registerDuration = getEnvVariable(dotenv, "RATE_LIMIT_REGISTER_IP_DURATION",
				ConfigDefaults.DEFAULT_RATE_LIMIT_DURATION);
		String loginIpCapacity = getEnvVariable(dotenv, "RATE_LIMIT_LOGIN_IP_CAPACITY",
				ConfigDefaults.DEFAULT_LOGIN_IP_CAPACITY);
		String loginIpDuration = getEnvVariable(dotenv, "RATE_LIMIT_LOGIN_IP_DURATION",
				ConfigDefaults.DEFAULT_RATE_LIMIT_DURATION);
		String loginUserCapacity = getEnvVariable(dotenv, "RATE_LIMIT_LOGIN_USER_CAPACITY",
				ConfigDefaults.DEFAULT_LOGIN_USER_CAPACITY);
		String loginUserDuration = getEnvVariable(dotenv, "RATE_LIMIT_LOGIN_USER_DURATION",
				ConfigDefaults.DEFAULT_RATE_LIMIT_DURATION);

		validateNumericConfig("RATE_LIMIT_REGISTER_IP_CAPACITY", registerCapacity);
		validateNumericConfig("RATE_LIMIT_LOGIN_IP_CAPACITY", loginIpCapacity);
		validateNumericConfig("RATE_LIMIT_LOGIN_USER_CAPACITY", loginUserCapacity);

		System.setProperty("rate-limit.register.ip.capacity", registerCapacity);
		System.setProperty("rate-limit.register.ip.refill-duration", registerDuration);
		System.setProperty("rate-limit.login.ip.capacity", loginIpCapacity);
		System.setProperty("rate-limit.login.ip.refill-duration", loginIpDuration);
		System.setProperty("rate-limit.login.user.capacity", loginUserCapacity);
		System.setProperty("rate-limit.login.user.refill-duration", loginUserDuration);

		logger.info("🎛️ Rate Limiting configurado para preproducción");
	}

	private static void validateDatabaseConfig(Dotenv dotenv) {
		String dbUrl = getEnvVariable(dotenv, "DB_URL");
		String dbUser = getEnvVariable(dotenv, "DB_USERNAME");
		String dbPass = getEnvVariable(dotenv, "DB_PASSWORD");
		String environment = getEnvVariable(dotenv, ConfigDefaults.ENVIRONMENT_KEY);

		// Validaciones obligatorias
		if (dbUrl == null || dbUrl.trim().isEmpty()) {
			throw new IllegalStateException("DB_URL no configurado");
		}
		if (dbUser == null || dbUser.trim().isEmpty()) {
			throw new IllegalStateException("DB_USERNAME no configurado");
		}

		dbPass = validateDbPassword(dbPass, environment);

		if (!dbUrl.startsWith("jdbc:")) {
			throw new IllegalStateException("Formato de DB_URL inválido");
		}

		System.setProperty("spring.datasource.url", dbUrl);
		System.setProperty("spring.datasource.username", dbUser);
		System.setProperty("spring.datasource.password", dbPass);

		if (logger.isInfoEnabled()) {
			logger.info("💃 Base de datos: {}", maskUrl(dbUrl));
			logger.info("👤 Usuario: {}", maskUsername(dbUser));
			if (dbPass.isEmpty()) {
				logger.info("🔓 Password: (vacío - solo desarrollo/preproducción)");
			} else {
				logger.info("🔐 Password: (configurado)");
			}
		}
	}

	private static String validateDbPassword(String dbPass, String environment) {
		// Permitir DB_PASSWORD vacío solo en desarrollo y preproducción
		boolean isProductionEnv = "prod".equals(environment) || "production".equals(environment);
		if (isProductionEnv && (dbPass == null || dbPass.trim().isEmpty())) {
			throw new IllegalStateException("DB_PASSWORD no configurado en producción");
		}

		if (dbPass == null) {
			dbPass = "";
			logger.warn("⚠️ DB_PASSWORD vacío - Solo permitido en desarrollo/preproducción");
		}

		if (!dbPass.isEmpty() && (dbPass.equals("admin") || dbPass.equals("password") || dbPass.equals("123456"))) {
			throw new IllegalStateException("DB_PASSWORD inseguro");
		}

		return dbPass;
	}

	private static void validateSecurityConfig(Dotenv dotenv) {
		String jwtSecret = getEnvVariable(dotenv, "JWT_SECRET_KEY");
		if (jwtSecret == null || jwtSecret.trim().isEmpty()) {
			throw new IllegalStateException("JWT_SECRET_KEY no configurado");
		}
		if (jwtSecret.length() < ConfigDefaults.MIN_JWT_SECRET_LENGTH) {
			throw new IllegalStateException("JWT_SECRET_KEY demasiado corto");
		}
		System.setProperty("jwt.secret", jwtSecret);
		String accessExp = getEnvVariable(dotenv, "JWT_ACCESS_EXPIRATION", ConfigDefaults.DEFAULT_ACCESS_EXPIRATION);
		String refreshExp = getEnvVariable(dotenv, "JWT_REFRESH_EXPIRATION", ConfigDefaults.DEFAULT_REFRESH_EXPIRATION);
		validateNumericConfig("JWT_ACCESS_EXPIRATION", accessExp);
		validateNumericConfig("JWT_REFRESH_EXPIRATION", refreshExp);
		System.setProperty("jwt.access-token-expiration", accessExp);
		System.setProperty("jwt.refresh-token-expiration", refreshExp);
		logger.info("🔐 JWT Secret length: {} caracteres", jwtSecret.length());
	}

	private static void validateAdminConfig(Dotenv dotenv) {
		String adminUsername = getEnvVariable(dotenv, "ADMIN_USERNAME");
		String adminEmail = getEnvVariable(dotenv, "ADMIN_EMAIL");
		String adminPassword = getEnvVariable(dotenv, "ADMIN_PASSWORD");
		String environment = getEnvVariable(dotenv, ConfigDefaults.ENVIRONMENT_KEY);

		// Validaciones obligatorias
		if (adminUsername == null || adminUsername.trim().isEmpty()) {
			throw new IllegalStateException("ADMIN_USERNAME no configurado");
		}
		if (adminEmail == null || adminEmail.trim().isEmpty()) {
			throw new IllegalStateException("ADMIN_EMAIL no configurado");
		}
		if (adminPassword == null || adminPassword.trim().isEmpty()) {
			throw new IllegalStateException("ADMIN_PASSWORD no configurado");
		}

		// Validaciones de seguridad solo en producción
		boolean isProductionEnv = "prod".equals(environment) || "production".equals(environment);
		if (isProductionEnv) {
			if (adminUsername.equals("admin") || adminUsername.equals("administrator")) {
				throw new IllegalStateException("ADMIN_USERNAME no puede ser un valor por defecto en producción");
			}
		}

		if (!isValidEmail(adminEmail)) {
			throw new IllegalStateException("ADMIN_EMAIL inválido");
		}

		if (!isPasswordSecure(adminPassword)) {
			throw new IllegalStateException("ADMIN_PASSWORD no es segura");
		}

		System.setProperty("admin.username", adminUsername);
		System.setProperty("admin.email", adminEmail);
		System.setProperty("admin.password", adminPassword);

		logger.info("👑 Admin username: {}", adminUsername);
		if (logger.isInfoEnabled()) {
			logger.info("📧 Admin email: {}", maskEmail(adminEmail));
		}
		logger.info("🎫 Los códigos de invitación serán creados por el administrador");
	}

	private static String getEnvVariable(Dotenv dotenv, String key, String defaultValue) {
		String value = System.getProperty(key);
		if (value == null) {
			value = System.getenv(key);
		}
		if (value == null && dotenv != null) {
			value = dotenv.get(key);
		}
		return value != null ? value : defaultValue;
	}

	private static String getEnvVariable(Dotenv dotenv, String key) {
		return getEnvVariable(dotenv, key, null);
	}

	private static void validateNumericConfig(String configName, String value) {
		try {
			long numValue = Long.parseLong(value);
			if (numValue <= 0) {
				throw new IllegalStateException(configName + " debe ser positivo");
			}
		} catch (NumberFormatException e) {
			throw new IllegalStateException(configName + " no es un número válido");
		}
	}

	private static boolean isValidEmail(String email) {
		if (email == null || email.trim().isEmpty()) {
			return false;
		}
		return email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$") &&
				!email.contains("..") &&
				!email.startsWith(".") &&
				!email.endsWith(".") &&
				email.length() <= 100;
	}

	private static boolean isPasswordSecure(String password) {
		if (password == null || password.length() < ConfigDefaults.MIN_PASSWORD_LENGTH) {
			return false;
		}
		boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
		boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
		boolean hasDigit = password.chars().anyMatch(Character::isDigit);
		boolean hasSymbol = password.chars().anyMatch(ch -> "@$!%*?&".indexOf(ch) >= 0);
		return hasLower && hasUpper && hasDigit && hasSymbol;
	}

	private static String maskUrl(String url) {
		return url.replaceAll("://([^:]+):([^@]+)@", "://*****:*****@");
	}

	private static String maskUsername(String username) {
		if (username.length() <= 2) {
			return "*".repeat(username.length());
		}
		return username.charAt(0) + "*".repeat(username.length() - 2) + username.charAt(username.length() - 1);
	}

	private static String maskEmail(String email) {
		if (email == null || !email.contains("@")) {
			return "null";
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