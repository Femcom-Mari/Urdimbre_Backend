package com.urdimbre.urdimbre.controller.admin;

import java.util.List;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.dto.user.UpdateRolesRequestDTO;
import com.urdimbre.urdimbre.dto.user.UserRegisterDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.service.user.UserService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
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
                        @Valid @RequestBody UserRegisterDTO userDTO, // ✅ SIN @Valid para saltarse validaciones
                        Authentication authentication) {

                log.info("👑 ADMIN {} creando organizador: {}",
                                authentication.getName(), userDTO.getUsername());

                userDTO.setInviteCode(null);

                Set<String> roles = Set.of("ORGANIZER", "USER");

                UserResponseDTO createdUser = userService.registerUserFromRegisterDTO(userDTO, roles);

                log.info("✅ Organizador {} creado exitosamente por ADMIN {} con roles: {}",
                                createdUser.getUsername(), authentication.getName(), createdUser.getRoles());

                return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
        }

        @PostMapping("/users/create-user")
        @PreAuthorize("hasRole('ADMIN')")
        @Operation(summary = "Crear usuario estándar", description = "Permite al ADMIN crear un usuario con rol USER")
        @ApiResponse(responseCode = "201", description = "Usuario creado exitosamente")
        @ApiResponse(responseCode = "400", description = "Datos inválidos")
        @ApiResponse(responseCode = "403", description = "Solo ADMIN puede crear usuarios")
        public ResponseEntity<UserResponseDTO> createUser(
                        @Valid @RequestBody UserRegisterDTO userDTO,
                        Authentication authentication) {

                log.info("👑 ADMIN {} creando usuario estándar: {}",
                                authentication.getName(), userDTO.getUsername());

                userDTO.setInviteCode(null);

                Set<String> roles = Set.of("USER");

                UserResponseDTO createdUser = userService.registerUserFromRegisterDTO(userDTO, roles);

                log.info("✅ Usuario {} creado exitosamente por ADMIN {} con roles: {}",
                                createdUser.getUsername(), authentication.getName(), createdUser.getRoles());

                return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
        }

        @PostMapping("/users/create-with-roles")
        @PreAuthorize("hasRole('ADMIN')")
        @Operation(summary = "Crear usuario con roles personalizados", description = "Permite al ADMIN crear un usuario con roles específicos")
        @ApiResponse(responseCode = "201", description = "Usuario creado exitosamente")
        @ApiResponse(responseCode = "400", description = "Datos inválidos")
        @ApiResponse(responseCode = "403", description = "Solo ADMIN puede crear usuarios")
        public ResponseEntity<UserResponseDTO> createUserWithRoles(
                        @Valid @RequestBody UserRegisterDTO userDTO,
                        @RequestParam(required = false) List<String> roles,
                        Authentication authentication) {

                log.info("👑 ADMIN {} creando usuario con roles personalizados: {} - Roles: {}",
                                authentication.getName(), userDTO.getUsername(), roles);

                userDTO.setInviteCode(null);

                if (roles == null || roles.isEmpty()) {
                        roles = List.of("USER");
                        log.info("🔄 No se especificaron roles, asignando USER por defecto");
                }

                Set<String> cleanRoles = Set.copyOf(roles);
                log.info("🎭 Roles finales: {}", cleanRoles);

                UserResponseDTO createdUser = userService.registerUserFromRegisterDTO(userDTO, cleanRoles);

                log.info("✅ Usuario {} creado exitosamente por ADMIN {} con roles: {}",
                                createdUser.getUsername(), authentication.getName(), createdUser.getRoles());

                return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
        }

        @PutMapping("/users/{id}/promote-to-organizer")
        @PreAuthorize("hasRole('ADMIN')")
        @Operation(summary = "Promover usuario a organizador", description = "Convierte un usuario existente en organizador")
        @ApiResponse(responseCode = "200", description = "Usuario promovido exitosamente")
        @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
        @ApiResponse(responseCode = "403", description = "Solo ADMIN puede promover usuarios")
        public ResponseEntity<UserResponseDTO> promoteToOrganizer(
                        @PathVariable Long id,
                        Authentication authentication) {

                log.info("🎭 ADMIN {} promoviendo usuario ID {} a organizador",
                                authentication.getName(), id);

                Set<String> roles = Set.of("USER", "ORGANIZER");
                UserResponseDTO updatedUser = userService.updateUserRoles(id, roles);

                log.info("✅ Usuario ID {} promovido a organizador por ADMIN {}: {}",
                                id, authentication.getName(), updatedUser.getRoles());

                return ResponseEntity.ok(updatedUser);
        }

        @PutMapping("/users/{id}/demote-from-organizer")
        @PreAuthorize("hasRole('ADMIN')")
        @Operation(summary = "Degradar organizador a usuario", description = "Remueve el rol ORGANIZER dejando solo USER")
        @ApiResponse(responseCode = "200", description = "Organizador degradado exitosamente")
        @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
        @ApiResponse(responseCode = "403", description = "Solo ADMIN puede degradar organizadores")
        public ResponseEntity<UserResponseDTO> demoteFromOrganizer(
                        @PathVariable Long id,
                        Authentication authentication) {

                log.info("🎭 ADMIN {} degradando organizador ID {} a usuario estándar",
                                authentication.getName(), id);

                Set<String> roles = Set.of("USER");
                UserResponseDTO updatedUser = userService.updateUserRoles(id, roles);

                log.info("✅ Organizador ID {} degradado a usuario por ADMIN {}: {}",
                                id, authentication.getName(), updatedUser.getRoles());

                return ResponseEntity.ok(updatedUser);
        }

        @PutMapping("/users/{id}/assign-roles")
        @PreAuthorize("hasRole('ADMIN')")
        @Operation(summary = "Asignar roles específicos", description = "Permite al ADMIN asignar roles específicos a un usuario")
        @ApiResponse(responseCode = "200", description = "Roles asignados exitosamente")
        @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
        @ApiResponse(responseCode = "403", description = "Solo ADMIN puede asignar roles")
        public ResponseEntity<UserResponseDTO> assignRoles(
                        @PathVariable Long id,
                        @Valid @RequestBody UpdateRolesRequestDTO request,
                        Authentication authentication) {

                log.info("🎭 ADMIN {} asignando roles al usuario ID {}: {}",
                                authentication.getName(), id, request.getRoles());

                UserResponseDTO updatedUser = userService.updateUserRoles(id, Set.copyOf(request.getRoles()));

                log.info("✅ Roles asignados exitosamente al usuario ID {} por ADMIN {}: {}",
                                id, authentication.getName(), updatedUser.getRoles());

                return ResponseEntity.ok(updatedUser);
        }

        @GetMapping("/users")
        @PreAuthorize("hasRole('ADMIN')")
        @Operation(summary = "Listar todos los usuarios", description = "Obtiene lista completa de usuarios para administración")
        @ApiResponse(responseCode = "200", description = "Lista obtenida exitosamente")
        @ApiResponse(responseCode = "403", description = "Solo ADMIN puede ver todos los usuarios")
        public ResponseEntity<List<UserResponseDTO>> getAllUsersForAdmin(Authentication authentication) {
                log.info("📋 ADMIN {} consultando lista completa de usuarios", authentication.getName());

                List<UserResponseDTO> users = userService.getAllUsers();

                log.info("✅ ADMIN {} obtuvo lista de {} usuarios", authentication.getName(), users.size());
                return ResponseEntity.ok(users);
        }

        @GetMapping("/users/organizers")
        @PreAuthorize("hasRole('ADMIN')")
        @Operation(summary = "Listar organizadores", description = "Obtiene lista de usuarios con rol ORGANIZER")
        @ApiResponse(responseCode = "200", description = "Lista de organizadores obtenida")
        @ApiResponse(responseCode = "403", description = "Solo ADMIN puede ver organizadores")
        public ResponseEntity<List<UserResponseDTO>> getAllOrganizers(Authentication authentication) {
                log.info("🏗️ ADMIN {} consultando lista de organizadores", authentication.getName());

                List<UserResponseDTO> organizers = userService.getUsersByRole("ORGANIZER");

                log.info("✅ ADMIN {} obtuvo lista de {} organizadores", authentication.getName(), organizers.size());
                return ResponseEntity.ok(organizers);
        }

        @GetMapping("/users/{id}")
        @PreAuthorize("hasRole('ADMIN')")
        @Operation(summary = "Ver detalles de usuario específico", description = "Obtiene información detallada de un usuario")
        @ApiResponse(responseCode = "200", description = "Usuario encontrado")
        @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
        @ApiResponse(responseCode = "403", description = "Solo ADMIN puede ver detalles de usuarios")
        public ResponseEntity<UserResponseDTO> getUserForAdmin(
                        @PathVariable Long id,
                        Authentication authentication) {

                log.info("👤 ADMIN {} consultando detalles del usuario ID {}", authentication.getName(), id);

                UserResponseDTO user = userService.getUser(id);

                return ResponseEntity.ok(user);
        }
}