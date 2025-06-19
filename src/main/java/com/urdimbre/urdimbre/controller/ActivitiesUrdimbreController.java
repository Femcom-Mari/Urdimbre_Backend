package com.urdimbre.urdimbre.controller;

import java.time.LocalDate;
import java.util.List;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreRequestDTO;
import com.urdimbre.urdimbre.dto.activities_urdimbre.ActivitiesUrdimbreResponseDTO;
import com.urdimbre.urdimbre.service.activities_urdimbre.ActivitiesUrdimbreService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/activities")
@Tag(name = "Activities", description = "API para gestión de actividades/eventos de Urdimbre")
@SecurityRequirement(name = "Bearer Authentication")
@Slf4j
public class ActivitiesUrdimbreController {

    private final ActivitiesUrdimbreService activitiesUrdimbreService;

    // ================================
    // ENDPOINTS DE LECTURA - Todos los usuarios autenticados
    // ================================

    @GetMapping
    @Operation(summary = "Obtener todas las actividades", description = "Devuelve todas las actividades disponibles con paginación")
    @ApiResponse(responseCode = "200", description = "Lista de actividades obtenida con éxito")
    public ResponseEntity<List<ActivitiesUrdimbreResponseDTO>> getAllActivities(
            @Parameter(description = "Número de página (0-indexado)") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Tamaño de página") @RequestParam(defaultValue = "15") int size) {

        log.info("📋 Obteniendo todas las actividades - página: {}, tamaño: {}", page, size);
        List<ActivitiesUrdimbreResponseDTO> activities = activitiesUrdimbreService.getAllActivities(page, size);
        return ResponseEntity.ok(activities);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Obtener actividad por ID", description = "Devuelve una actividad específica por su ID")
    @ApiResponse(responseCode = "200", description = "Actividad encontrada con éxito")
    @ApiResponse(responseCode = "404", description = "Actividad no encontrada", content = @Content)
    public ResponseEntity<ActivitiesUrdimbreResponseDTO> getActivityById(
            @Parameter(description = "ID de la actividad") @PathVariable Long id) {

        log.info("🔍 Obteniendo actividad con ID: {}", id);
        ActivitiesUrdimbreResponseDTO activity = activitiesUrdimbreService.getActivityById(id);
        return ResponseEntity.ok(activity);
    }

    @GetMapping("/category/{category}")
    @Operation(summary = "Obtener actividades por categoría", description = "Devuelve todas las actividades de una categoría específica")
    @ApiResponse(responseCode = "200", description = "Actividades por categoría obtenidas con éxito")
    public ResponseEntity<List<ActivitiesUrdimbreResponseDTO>> getActivitiesByCategory(
            @Parameter(description = "Categoría de actividades (SPORT, ARTISTIC, CULTURAL)") @PathVariable String category,
            @Parameter(description = "Número de página") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Tamaño de página") @RequestParam(defaultValue = "15") int size) {

        log.info("📂 Obteniendo actividades por categoría: {} - página: {}, tamaño: {}", category, page, size);
        List<ActivitiesUrdimbreResponseDTO> activities = activitiesUrdimbreService.getActivitiesByCategory(category);
        return ResponseEntity.ok(activities);
    }

    @GetMapping("/schedule/{date}")
    @Operation(summary = "Obtener actividades por fecha", description = "Devuelve todas las actividades de una fecha específica")
    @ApiResponse(responseCode = "200", description = "Actividades por fecha obtenidas con éxito")
    public ResponseEntity<List<ActivitiesUrdimbreResponseDTO>> getActivitiesByDate(
            @Parameter(description = "Fecha en formato yyyy-MM-dd") @PathVariable @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {

        log.info("📅 Obteniendo actividades para la fecha: {}", date);
        List<ActivitiesUrdimbreResponseDTO> activities = activitiesUrdimbreService.getActivitiesByDate(date);
        return ResponseEntity.ok(activities);
    }

    @GetMapping("/upcoming")
    @Operation(summary = "Obtener próximas actividades", description = "Devuelve las actividades programadas para fechas futuras")
    @ApiResponse(responseCode = "200", description = "Próximas actividades obtenidas con éxito")
    public ResponseEntity<List<ActivitiesUrdimbreResponseDTO>> getUpcomingActivities(
            @Parameter(description = "Número de días hacia adelante") @RequestParam(defaultValue = "30") int days,
            @Parameter(description = "Número de página") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Tamaño de página") @RequestParam(defaultValue = "15") int size) {

        log.info("⏰ Obteniendo próximas actividades para {} días", days);
        List<ActivitiesUrdimbreResponseDTO> activities = activitiesUrdimbreService.getUpcomingActivities(days, page,
                size);
        return ResponseEntity.ok(activities);
    }

    @GetMapping("/search")
    @Operation(summary = "Buscar actividades por título", description = "Busca actividades que contengan el texto especificado en el título")
    @ApiResponse(responseCode = "200", description = "Búsqueda realizada con éxito")
    public ResponseEntity<List<ActivitiesUrdimbreResponseDTO>> searchActivitiesByTitle(
            @Parameter(description = "Texto a buscar en el título") @RequestParam String title) {

        log.info("🔍 Buscando actividades por título: {}", title);
        List<ActivitiesUrdimbreResponseDTO> activities = activitiesUrdimbreService.searchActivitiesByTitle(title);
        return ResponseEntity.ok(activities);
    }

    // ================================
    // ENDPOINTS DE ESCRITURA - ORGANIZER y ADMIN solamente
    // ================================

    @PostMapping
    @PreAuthorize("hasRole('ORGANIZER') or hasRole('ADMIN')")
    @Operation(summary = "Crear nueva actividad", description = "Crea una nueva actividad (solo ORGANIZER y ADMIN)")
    @ApiResponse(responseCode = "201", description = "Actividad creada exitosamente")
    @ApiResponse(responseCode = "400", description = "Datos de actividad inválidos", content = @Content)
    @ApiResponse(responseCode = "403", description = "Sin permisos para crear actividades - Requiere rol ORGANIZER o ADMIN", content = @Content)
    public ResponseEntity<ActivitiesUrdimbreResponseDTO> createActivity(
            @Parameter(description = "Datos de la nueva actividad") @Valid @RequestBody ActivitiesUrdimbreRequestDTO dto) {

        log.info("✨ Creando nueva actividad: {}", dto.getTitle());
        ActivitiesUrdimbreResponseDTO createdActivity = activitiesUrdimbreService.createActivitiesUrdimbre(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdActivity);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ORGANIZER') or hasRole('ADMIN')")
    @Operation(summary = "Actualizar actividad", description = "Actualiza una actividad existente (solo ORGANIZER y ADMIN)")
    @ApiResponse(responseCode = "200", description = "Actividad actualizada con éxito")
    @ApiResponse(responseCode = "404", description = "Actividad no encontrada", content = @Content)
    @ApiResponse(responseCode = "403", description = "Sin permisos para actualizar actividades - Requiere rol ORGANIZER o ADMIN", content = @Content)
    public ResponseEntity<ActivitiesUrdimbreResponseDTO> updateActivity(
            @Parameter(description = "ID de la actividad a actualizar") @PathVariable Long id,
            @Parameter(description = "Nuevos datos de la actividad") @Valid @RequestBody ActivitiesUrdimbreRequestDTO dto) {

        log.info("🔄 Actualizando actividad con ID: {}", id);
        ActivitiesUrdimbreResponseDTO updatedActivity = activitiesUrdimbreService.updateActivity(id, dto);
        return ResponseEntity.ok(updatedActivity);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ORGANIZER') or hasRole('ADMIN')")
    @Operation(summary = "Eliminar actividad", description = "Elimina una actividad por su ID (solo ORGANIZER y ADMIN)")
    @ApiResponse(responseCode = "204", description = "Actividad eliminada con éxito")
    @ApiResponse(responseCode = "404", description = "Actividad no encontrada", content = @Content)
    @ApiResponse(responseCode = "403", description = "Sin permisos para eliminar actividades - Requiere rol ORGANIZER o ADMIN", content = @Content)
    public ResponseEntity<Void> deleteActivity(
            @Parameter(description = "ID de la actividad a eliminar") @PathVariable Long id) {

        log.info("🗑️ Eliminando actividad con ID: {}", id);
        activitiesUrdimbreService.deleteActivity(id);
        return ResponseEntity.noContent().build();
    }

    // ================================
    // ENDPOINTS ADMINISTRATIVOS - Solo ADMIN
    // ================================

    @GetMapping("/stats")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Estadísticas de actividades", description = "Obtiene estadísticas generales de actividades (solo ADMIN)")
    @ApiResponse(responseCode = "200", description = "Estadísticas obtenidas con éxito")
    @ApiResponse(responseCode = "403", description = "Sin permisos de administrador", content = @Content)
    public ResponseEntity<?> getActivitiesStats() {
        log.info("📊 Obteniendo estadísticas de actividades");
        // Implementar servicio de estadísticas
        return ResponseEntity.ok("Estadísticas de actividades - Por implementar");
    }

    @PostMapping("/{id}/toggle-status")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Cambiar estado de actividad", description = "Activa/desactiva una actividad (solo ADMIN)")
    @ApiResponse(responseCode = "200", description = "Estado cambiado con éxito")
    @ApiResponse(responseCode = "404", description = "Actividad no encontrada", content = @Content)
    @ApiResponse(responseCode = "403", description = "Sin permisos de administrador", content = @Content)
    public ResponseEntity<ActivitiesUrdimbreResponseDTO> toggleActivityStatus(
            @Parameter(description = "ID de la actividad") @PathVariable Long id) {

        log.info("🔄 Cambiando estado de actividad con ID: {}", id);
        // Implementar toggle de estado en el servicio
        return ResponseEntity.ok().build();
    }

    // ================================
    // ENDPOINTS ESPECIALES PARA ORGANIZADORES
    // ================================

    @GetMapping("/my-activities")
    @PreAuthorize("hasRole('ORGANIZER') or hasRole('ADMIN')")
    @Operation(summary = "Obtener mis actividades", description = "Obtiene las actividades creadas por el organizador actual")
    @ApiResponse(responseCode = "200", description = "Actividades del organizador obtenidas con éxito")
    @ApiResponse(responseCode = "403", description = "Sin permisos - Requiere rol ORGANIZER o ADMIN", content = @Content)
    public ResponseEntity<List<ActivitiesUrdimbreResponseDTO>> getMyActivities(
            @Parameter(description = "Número de página") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Tamaño de página") @RequestParam(defaultValue = "15") int size) {

        log.info("👤 Obteniendo actividades del organizador actual");
        // TODO: Implementar getActivitiesByOrganizer en el servicio
        return ResponseEntity.ok().build();
    }

    @GetMapping("/organizer-dashboard")
    @PreAuthorize("hasRole('ORGANIZER') or hasRole('ADMIN')")
    @Operation(summary = "Dashboard del organizador", description = "Obtiene resumen de actividades y estadísticas para el organizador")
    @ApiResponse(responseCode = "200", description = "Dashboard obtenido con éxito")
    @ApiResponse(responseCode = "403", description = "Sin permisos - Requiere rol ORGANIZER o ADMIN", content = @Content)
    public ResponseEntity<?> getOrganizerDashboard() {
        log.info("📊 Obteniendo dashboard del organizador");
        // TODO: Implementar dashboard específico para organizadores
        return ResponseEntity.ok("Dashboard del organizador - Por implementar");
    }
}