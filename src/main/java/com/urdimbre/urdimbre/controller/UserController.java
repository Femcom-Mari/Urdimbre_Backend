package com.urdimbre.urdimbre.controller;

import java.util.List;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.dto.user.UpdateRolesRequestDTO; // ✅ IMPORT CORRECTO
import com.urdimbre.urdimbre.dto.user.UserRequestDTO;
import com.urdimbre.urdimbre.dto.user.UserResponseDTO;
import com.urdimbre.urdimbre.service.user.UserService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "Users", description = "API para gestión de usuarios")
@Slf4j
public class UserController {

    private final UserService userService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Obtener todos los usuarios", description = "Devuelve un listado de todos los usuarios registrados - SOLO ADMIN")
    @ApiResponse(responseCode = "200", description = "Lista de usuarios obtenida con éxito")
    public ResponseEntity<List<UserResponseDTO>> getAllUsers() {
        log.info("📋 ADMIN solicitando lista de todos los usuarios");
        List<UserResponseDTO> users = userService.getAllUsers();
        log.info("✅ Devolviendo {} usuarios", users.size());
        return ResponseEntity.ok(users);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Obtener usuario por ID", description = "Devuelve un usuario según su ID")
    @ApiResponse(responseCode = "200", description = "Usuario encontrado con éxito")
    @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content)
    public ResponseEntity<UserResponseDTO> getUserById(@PathVariable Long id, Authentication authentication) {
        log.info("👤 Usuario {} solicitando datos del usuario ID: {}", authentication.getName(), id);
        UserResponseDTO user = userService.getUser(id);
        return ResponseEntity.ok(user);
    }

    @GetMapping("/me")
    @Operation(summary = "Obtener usuario actual", description = "Devuelve los datos del usuario autenticado")
    @ApiResponse(responseCode = "200", description = "Usuario actual obtenido")
    public ResponseEntity<UserResponseDTO> getCurrentUser(Authentication authentication) {
        String username = authentication.getName();
        log.info("👤 Usuario {} solicitando sus propios datos", username);
        UserResponseDTO user = userService.getUserByUsername(username);
        return ResponseEntity.ok(user);
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Crear nuevo usuario", description = "Crea un nuevo usuario en el sistema - SOLO ADMIN puede crear usuarios sin código de invitación")
    @ApiResponse(responseCode = "201", description = "Usuario creado exitosamente")
    @ApiResponse(responseCode = "400", description = "Datos de usuario inválidos", content = @Content)
    @ApiResponse(responseCode = "403", description = "Solo ADMIN puede crear usuarios", content = @Content)
    public ResponseEntity<UserResponseDTO> createUser(
            @Valid @RequestBody UserRequestDTO userDTO,
            @RequestParam(required = false) List<String> roles,
            Authentication authentication) {

        log.info("👑 ADMIN {} creando usuario {} sin código de invitación",
                authentication.getName(), userDTO.getUsername());
        log.info("🎭 Roles solicitados: {}", roles);

        // ✅ Si no se especifican roles, asignar USER por defecto
        if (roles == null || roles.isEmpty()) {
            roles = List.of("USER");
            log.info("🔄 No se especificaron roles, asignando USER por defecto");
        }

        // ✅ Limpiar y validar roles
        Set<String> cleanRoles = Set.copyOf(roles);
        log.info("🎭 Roles finales para creación: {}", cleanRoles);

        UserResponseDTO createdUser = userService.registerUser(userDTO, cleanRoles);

        log.info("✅ Usuario {} creado exitosamente por ADMIN {} con roles: {}",
                createdUser.getUsername(), authentication.getName(), createdUser.getRoles());

        return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    @Operation(summary = "Actualizar usuario", description = "Actualiza los datos de un usuario existente")
    @ApiResponse(responseCode = "200", description = "Usuario actualizado con éxito")
    @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content)
    public ResponseEntity<UserResponseDTO> updateUser(
            @PathVariable Long id,
            @Valid @RequestBody UserRequestDTO userDTO,
            Authentication authentication) {

        log.info("📝 Usuario {} actualizando datos del usuario ID: {}", authentication.getName(), id);
        UserResponseDTO updatedUser = userService.updateUser(id, userDTO);
        log.info("✅ Usuario ID {} actualizado exitosamente", id);

        return ResponseEntity.ok(updatedUser);
    }

    // ✅ ENDPOINT PARA CAMBIAR ROLES - SOLO ADMIN
    @PutMapping("/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Actualizar roles de usuario", description = "Permite al ADMIN cambiar los roles de un usuario")
    @ApiResponse(responseCode = "200", description = "Roles actualizados con éxito")
    @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content)
    @ApiResponse(responseCode = "403", description = "Solo ADMIN puede cambiar roles", content = @Content)
    public ResponseEntity<UserResponseDTO> updateUserRoles(
            @PathVariable Long id,
            @Valid @RequestBody UpdateRolesRequestDTO request, // ✅ USANDO DTO SEPARADO
            Authentication authentication) {

        log.info("🎭 ADMIN {} actualizando roles del usuario ID: {} a roles: {}",
                authentication.getName(), id, request.getRoles());

        UserResponseDTO updatedUser = userService.updateUserRoles(id, Set.copyOf(request.getRoles()));

        log.info("✅ Roles actualizados exitosamente para usuario ID {} por ADMIN {}: {}",
                id, authentication.getName(), updatedUser.getRoles());

        return ResponseEntity.ok(updatedUser);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Eliminar usuario", description = "Elimina un usuario por su ID - SOLO ADMIN")
    @ApiResponse(responseCode = "204", description = "Usuario eliminado con éxito")
    @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content)
    @ApiResponse(responseCode = "403", description = "Solo ADMIN puede eliminar usuarios", content = @Content)
    public ResponseEntity<Void> deleteUser(@PathVariable Long id, Authentication authentication) {
        log.info("🗑️ ADMIN {} eliminando usuario ID: {}", authentication.getName(), id);
        userService.deleteUser(id);
        log.info("✅ Usuario ID {} eliminado exitosamente por ADMIN {}", id, authentication.getName());
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{id}/change-password")
    @Operation(summary = "Cambiar contraseña", description = "Permite cambiar la contraseña de un usuario")
    @ApiResponse(responseCode = "200", description = "Contraseña cambiada con éxito")
    @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content)
    @ApiResponse(responseCode = "400", description = "Contraseña actual incorrecta", content = @Content)
    public ResponseEntity<UserResponseDTO> changePassword(
            @PathVariable Long id,
            @RequestParam String currentPassword,
            @RequestParam String newPassword,
            Authentication authentication) {

        log.info("🔐 Usuario {} cambiando contraseña para usuario ID: {}", authentication.getName(), id);
        UserResponseDTO user = userService.changePassword(id, currentPassword, newPassword);
        log.info("✅ Contraseña cambiada exitosamente para usuario ID: {}", id);

        return ResponseEntity.ok(user);
    }
}