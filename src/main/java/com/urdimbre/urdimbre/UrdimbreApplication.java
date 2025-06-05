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
			// 🔐 CARGAR VARIABLES DE ENTORNO DESDE .env
			loadEnvironmentVariables();

			// 🚀 INICIAR APLICACIÓN SPRING BOOT
			SpringApplication.run(UrdimbreApplication.class, args);

			logger.info("✅ Aplicación Urdimbre iniciada correctamente");

		} catch (Exception e) {
			logger.error("❌ Error iniciando aplicación: {}", e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * 🔐 Cargar y validar variables de entorno
	 */
	private static void loadEnvironmentVariables() {
		logger.info("🔧 Cargando variables de entorno...");

		// ✅ CARGAR .env CON CONFIGURACIÓN SEGURA
		Dotenv dotenv = Dotenv.configure()
				.ignoreIfMissing() // No fallar si .env no existe (para contenedores)
				.load();

		// 🗃️ VALIDAR VARIABLES DE BASE DE DATOS
		validateDatabaseConfig(dotenv);

		// 🔐 VALIDAR VARIABLES DE SEGURIDAD
		validateSecurityConfig(dotenv);

		// 👑 VALIDAR VARIABLES DE ADMINISTRADOR
		validateAdminConfig(dotenv);

		logger.info("✅ Variables de entorno cargadas y validadas correctamente");
	}

	/**
	 * 🗃️ Validar configuración de base de datos
	 */
	private static void validateDatabaseConfig(Dotenv dotenv) {
		String dbUrl = getEnvVariable(dotenv, "DB_URL");
		String dbUser = getEnvVariable(dotenv, "DB_USERNAME");
		String dbPass = getEnvVariable(dotenv, "DB_PASSWORD");

		if (dbUrl == null || dbUser == null || dbPass == null) {
			logger.error("❌ ERROR: Faltan variables de entorno para la base de datos");
			logger.error("Variables requeridas: DB_URL, DB_USERNAME, DB_PASSWORD");
			throw new IllegalStateException("Configuración de base de datos incompleta");
		}

		// ✅ VALIDAR FORMATO DE URL
		if (!dbUrl.startsWith("jdbc:")) {
			logger.error("❌ ERROR: DB_URL debe comenzar con 'jdbc:'");
			throw new IllegalStateException("Formato de DB_URL inválido");
		}

		// ✅ ESTABLECER PROPIEDADES DEL SISTEMA
		System.setProperty("DB_URL", dbUrl);
		System.setProperty("DB_USERNAME", dbUser);
		System.setProperty("DB_PASSWORD", dbPass);

		logger.info("✅ Configuración de base de datos validada");
		if (logger.isInfoEnabled()) {
			logger.info("🗃️ Base de datos: {}", maskUrl(dbUrl));
		}
	}

	/**
	 * 🔐 Validar configuración de seguridad
	 */
	private static void validateSecurityConfig(Dotenv dotenv) {
		String jwtSecret = getEnvVariable(dotenv, "JWT_SECRET_KEY");

		if (jwtSecret == null || jwtSecret.trim().isEmpty()) {
			logger.error("❌ ERROR: JWT_SECRET_KEY no está configurado");
			logger.error("Genera uno con: openssl rand -hex 64");
			throw new IllegalStateException("JWT_SECRET_KEY no configurado");
		}

		// ✅ VALIDAR LONGITUD MÍNIMA
		if (jwtSecret.length() < 64) {
			logger.error("❌ ERROR: JWT_SECRET_KEY debe tener al menos 64 caracteres");
			logger.error("Actual: {} caracteres", jwtSecret.length());
			logger.error("Genera uno nuevo con: openssl rand -hex 64");
			throw new IllegalStateException("JWT_SECRET_KEY demasiado corto");
		}

		// ✅ VALIDAR QUE SEA HEXADECIMAL
		if (!jwtSecret.matches("^[0-9a-fA-F]+$")) {
			logger.warn("⚠️ JWT_SECRET_KEY no parece ser hexadecimal puro");
		}

		// ✅ ESTABLECER PROPIEDADES DEL SISTEMA
		System.setProperty("JWT_SECRET_KEY", jwtSecret);

		// 🔐 CONFIGURAR TIEMPOS DE EXPIRACIÓN
		String accessExp = getEnvVariable(dotenv, "JWT_ACCESS_EXPIRATION", "900000");
		String refreshExp = getEnvVariable(dotenv, "JWT_REFRESH_EXPIRATION", "86400000");

		System.setProperty("JWT_ACCESS_EXPIRATION", accessExp);
		System.setProperty("JWT_REFRESH_EXPIRATION", refreshExp);

		logger.info("✅ Configuración de seguridad validada");
		logger.info("🔐 JWT Secret length: {} caracteres", jwtSecret.length());
		logger.info("⏰ Access token expiration: {} ms", accessExp);
		logger.info("⏰ Refresh token expiration: {} ms", refreshExp);
	}

	/**
	 * 👑 Validar configuración del administrador
	 */
	private static void validateAdminConfig(Dotenv dotenv) {
		String adminUsername = getEnvVariable(dotenv, "ADMIN_USERNAME", "admin");
		String adminEmail = getEnvVariable(dotenv, "ADMIN_EMAIL");
		String adminPassword = getEnvVariable(dotenv, "ADMIN_PASSWORD");

		if (adminEmail == null || adminPassword == null) {
			logger.warn("⚠️ ADMIN_EMAIL o ADMIN_PASSWORD no configurados");
			logger.warn("Se usarán valores por defecto (NO RECOMENDADO PARA PRODUCCIÓN)");
		}

		// ✅ VALIDAR CONTRASEÑA SEGURA
		if (adminPassword != null && !isPasswordSecure(adminPassword)) {
			logger.error("❌ ERROR: ADMIN_PASSWORD no es suficientemente segura");
			logger.error("Debe tener al menos 8 caracteres, mayúscula, minúscula, número y símbolo");
			throw new IllegalStateException("ADMIN_PASSWORD no es segura");
		}

		// ✅ ESTABLECER PROPIEDADES DEL SISTEMA
		System.setProperty("ADMIN_USERNAME", adminUsername);
		if (adminEmail != null)
			System.setProperty("ADMIN_EMAIL", adminEmail);
		if (adminPassword != null)
			System.setProperty("ADMIN_PASSWORD", adminPassword);

		// 🎟️ CÓDIGO DE INVITACIÓN
		String inviteCode = getEnvVariable(dotenv, "INVITE_CODE", "URDIMBRE2025");
		System.setProperty("INVITE_CODE", inviteCode);

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

	/**
	 * 🔍 Obtener variable de entorno con fallback
	 */
	private static String getEnvVariable(Dotenv dotenv, String key) {
		return getEnvVariable(dotenv, key, null);
	}

	private static String getEnvVariable(Dotenv dotenv, String key, String defaultValue) {
		// Prioridad: Variables del sistema > .env > valor por defecto
		String value = System.getenv(key);
		if (value == null && dotenv != null) {
			value = dotenv.get(key);
		}
		return value != null ? value : defaultValue;
	}

	/**
	 * 🔐 Validar que la contraseña sea segura
	 */
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

	/**
	 * 🎭 Enmascarar URL para logs
	 */
	private static String maskUrl(String url) {
		if (url == null)
			return "null";
		return url.replaceAll("://([^:]+):([^@]+)@", "://*****:*****@");
	}

	/**
	 * 📧 Enmascarar email para logs
	 */
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