package com.urdimbre.urdimbre;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.github.cdimascio.dotenv.Dotenv;

@SpringBootApplication
public class UrdimbreApplication {

	public static void main(String[] args) {
		Dotenv dotenv = Dotenv.configure()
				.directory("./Urdimbre_Backend")
				.ignoreIfMissing()
				.load();

		String dbUrl = dotenv.get("DB_URL");
		String dbUser = dotenv.get("DB_USERNAME");
		String dbPass = dotenv.get("DB_PASSWORD");

		if (dbUrl == null || dbUser == null || dbPass == null) {
			System.err.println("❌ ERROR: Faltan variables de entorno para la conexión a la base de datos.");
			System.err.println("Verifica que .env tenga DB_URL, DB_USERNAME y DB_PASSWORD.");
			System.exit(1);
		}

		System.setProperty("DB_URL", dbUrl);
		System.setProperty("DB_USERNAME", dbUser);
		System.setProperty("DB_PASSWORD", dbPass);

		SpringApplication.run(UrdimbreApplication.class, args);
		System.out.println("✅ Aplicación iniciada correctamente y variables de entorno cargadas.");
	}
}
