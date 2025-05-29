package com.urdimbre.urdimbre.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.urdimbre.urdimbre.model.Role;
import com.urdimbre.urdimbre.repository.RoleRepository;

@Configuration
public class DataInitializer {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Bean
    public CommandLineRunner initData(RoleRepository roleRepository) {
        return args -> {
            initRoles(roleRepository);
        };
    }

    private void initRoles(RoleRepository roleRepository) {
        logger.info("Iniciando creación de roles...");

        if (roleRepository.findByName("ROLE_USER").isEmpty()) {
            logger.info("Creando rol ROLE_USER");
            Role userRole = new Role();
            userRole.setName("ROLE_USER");
            userRole.setDescription("Rol por defecto para usuarios registrados");
            roleRepository.save(userRole);
            logger.info("Rol ROLE_USER creado exitosamente");
        } else {
            logger.info("Rol ROLE_USER ya existe, no es necesario crearlo");
        }

        if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
            logger.info("Creando rol ROLE_ADMIN");
            Role adminRole = new Role();
            adminRole.setName("ROLE_ADMIN");
            adminRole.setDescription("Rol para administradores");
            roleRepository.save(adminRole);
            logger.info("Rol ROLE_ADMIN creado exitosamente");
        } else {
            logger.info("Rol ROLE_ADMIN ya existe, no es necesario crearlo");
        }

        logger.info("Total de roles disponibles en el sistema: {}", roleRepository.count());
    }
}