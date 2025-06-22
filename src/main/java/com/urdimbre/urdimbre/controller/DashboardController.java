package com.urdimbre.urdimbre.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.dto.dashboard.DashboardDTO;
import com.urdimbre.urdimbre.service.dashboard.DashboardService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Dashboard", description = "API para dashboard de administración y organizadores")
@SecurityRequirement(name = "Bearer Authentication")
public class DashboardController {

    private final DashboardService dashboardService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'ORGANIZER')")
    @Operation(summary = "Obtener dashboard", description = "Obtiene datos del dashboard según el rol del usuario (ADMIN ve todo, ORGANIZER ve sus datos)")
    @ApiResponse(responseCode = "200", description = "Dashboard obtenido exitosamente")
    @ApiResponse(responseCode = "403", description = "Sin permisos - Requiere rol ADMIN o ORGANIZER")
    public ResponseEntity<DashboardDTO> getDashboard(Authentication authentication) {
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .toList();

        log.info("📥 Petición de dashboard por usuario: {} con roles: {}", username, roles);

        DashboardService.UserContext userContext = new DashboardService.UserContext(username, roles);
        DashboardDTO dashboard = dashboardService.getDashboardData(userContext);

        log.info("✅ Dashboard generado exitosamente para usuario: {}", username);
        return ResponseEntity.ok(dashboard);
    }

    @GetMapping("/activities-summary")
    @PreAuthorize("hasAnyRole('ADMIN', 'ORGANIZER')")
    @Operation(summary = "Resumen de actividades", description = "Obtiene un resumen detallado de actividades")
    @ApiResponse(responseCode = "200", description = "Resumen obtenido exitosamente")
    @ApiResponse(responseCode = "403", description = "Sin permisos - Requiere rol ADMIN o ORGANIZER")
    public ResponseEntity<?> getActivitiesSummary(Authentication authentication) {
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .toList();

        log.info("📊 Obteniendo resumen de actividades para usuario: {}", username);

        DashboardService.UserContext userContext = new DashboardService.UserContext(username, roles);
        var summary = dashboardService.getActivitiesSummary(userContext);

        return ResponseEntity.ok(summary);
    }

    @GetMapping("/recent-activities")
    @PreAuthorize("hasAnyRole('ADMIN', 'ORGANIZER')")
    @Operation(summary = "Actividades recientes", description = "Obtiene las actividades más recientes")
    @ApiResponse(responseCode = "200", description = "Actividades recientes obtenidas")
    @ApiResponse(responseCode = "403", description = "Sin permisos - Requiere rol ADMIN o ORGANIZER")
    public ResponseEntity<?> getRecentActivities(Authentication authentication) {
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .toList();

        log.info("⏰ Obteniendo actividades recientes para usuario: {}", username);

        DashboardService.UserContext userContext = new DashboardService.UserContext(username, roles);
        var recentActivities = dashboardService.getRecentActivities(userContext);

        return ResponseEntity.ok(recentActivities);
    }

    @GetMapping("/stats")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Estadísticas del sistema", description = "Obtiene estadísticas completas del sistema (solo ADMIN)")
    @ApiResponse(responseCode = "200", description = "Estadísticas obtenidas")
    @ApiResponse(responseCode = "403", description = "Sin permisos de administrador")
    public ResponseEntity<?> getSystemStats(Authentication authentication) {
        String username = authentication.getName();

        log.info("📈 Obteniendo estadísticas del sistema para ADMIN: {}", username);

        var stats = dashboardService.getSystemStats();

        return ResponseEntity.ok(stats);
    }
}