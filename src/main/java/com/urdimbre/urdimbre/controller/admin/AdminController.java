package com.urdimbre.urdimbre.controller.admin;

import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.dto.user.UserRegisterDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.service.user.UserService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Tag(name = "Admin", description = "API para funciones administrativas")
@Slf4j
public class AdminController {

        private final UserService userService;

        @PostMapping("/users/create-organizer")
        @PreAuthorize("hasRole('ADMIN')")
        @Operation(summary = "Crear organizador", description = "Permite al ADMIN crear un usuario con rol ORGANIZER")
        @ApiResponse(responseCode = "201", description = "Organizador creado exitosamente")
        @ApiResponse(responseCode = "400", description = "Datos inválidos")
        @ApiResponse(responseCode = "403", description = "Solo ADMIN puede crear organizadores")
        public ResponseEntity<UserResponseDTO> createOrganizer(
                        @RequestBody UserRegisterDTO userDTO, // ✅ SIN @Valid para saltarse validaciones
                        Authentication authentication) {

                log.info("👑 ADMIN {} creando organizador: {}",
                                authentication.getName(), userDTO.getUsername());

                // ✅ Para ADMIN, limpiar invite code (será ignorado en UserService)
                userDTO.setInviteCode(null);

                // ✅ Crear usuario con rol ORGANIZER y USER (rol base)
                Set<String> roles = Set.of("ORGANIZER", "USER");

                UserResponseDTO createdUser = userService.registerUserFromRegisterDTO(userDTO, roles);

                log.info("✅ Organizador {} creado exitosamente por ADMIN {} con roles: {}",
                                createdUser.getUsername(), authentication.getName(), createdUser.getRoles());

                return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
        }
}