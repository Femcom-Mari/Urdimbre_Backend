package com.urdimbre.urdimbre.controller.admin;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.dto.invite.BulkInviteCodeRequestDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodeRequestDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodeResponseDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodeStatsDTO;
import com.urdimbre.urdimbre.service.invite.InviteCodeService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/admin/invite-codes")
@RequiredArgsConstructor
@Slf4j
public class InviteCodeController {

    private final InviteCodeService inviteCodeService;

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<InviteCodeResponseDTO> generateCode(@Valid @RequestBody InviteCodeRequestDTO request) {
        log.info("🎟️ Admin generando código de invitación");

        InviteCodeResponseDTO response = inviteCodeService.generateCode(request);

        log.info("✅ Código generado: {} (expira en {} horas)",
                response.getCode(), request.getDurationHours());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/bulk")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<InviteCodeResponseDTO>> generateBulkCodes(
            @Valid @RequestBody BulkInviteCodeRequestDTO request) {
        log.info("🎯 Admin generando {} códigos en lote", request.getQuantity());

        List<InviteCodeResponseDTO> response = inviteCodeService.generateBulkCodes(request);

        log.info("✅ {} códigos generados en lote", response.size());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<InviteCodeResponseDTO>> getAllCodes(@PageableDefault(size = 20) Pageable pageable) {
        log.debug("📋 Admin consultando códigos de invitación");

        Page<InviteCodeResponseDTO> codes = inviteCodeService.getAllCodes(pageable);

        return ResponseEntity.ok(codes);
    }

    @GetMapping("/my-codes")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<InviteCodeResponseDTO>> getMyCodes(@PageableDefault(size = 20) Pageable pageable) {
        log.debug("📋 Admin consultando sus códigos de invitación");

        Page<InviteCodeResponseDTO> codes = inviteCodeService.getUserCodes(pageable);

        return ResponseEntity.ok(codes);
    }

    @GetMapping("/validate")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Boolean> validateCode(@RequestParam String code) {
        log.debug("✅ Validando código: {}", code);

        boolean isValid = inviteCodeService.validateInviteCode(code);

        return ResponseEntity.ok(isValid);
    }

    @GetMapping("/stats")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<InviteCodeStatsDTO> getStatistics() {
        log.debug("📊 Admin consultando estadísticas de códigos");

        InviteCodeStatsDTO stats = inviteCodeService.getStatistics();

        return ResponseEntity.ok(stats);
    }

    @PutMapping("/{id}/revoke")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<InviteCodeResponseDTO> revokeCode(@PathVariable Long id) {
        log.info("🚫 Admin revocando código ID: {}", id);

        InviteCodeResponseDTO response = inviteCodeService.revokeCode(id);

        log.info("✅ Código revocado: {}", response.getCode());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/cleanup")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> cleanupExpiredCodes() {
        log.info("🧹 Admin ejecutando limpieza manual de códigos");

        int cleaned = inviteCodeService.manualCleanup();

        return ResponseEntity.ok("Limpieza completada: " + cleaned + " códigos procesados");
    }

    @GetMapping("/most-used")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<InviteCodeResponseDTO>> getMostUsedCodes(@PageableDefault(size = 10) Pageable pageable) {
        log.debug("📈 Admin consultando códigos más usados");

        Page<InviteCodeResponseDTO> codes = inviteCodeService.getMostUsedCodes(pageable);

        return ResponseEntity.ok(codes);
    }

    @GetMapping("/by-status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<InviteCodeResponseDTO>> getCodesByStatus(
            @RequestParam String status,
            @PageableDefault(size = 20) Pageable pageable) {

        log.debug("🔍 Admin buscando códigos con estado: {}", status);

        Page<InviteCodeResponseDTO> codes = inviteCodeService.getCodesByStatus(status, pageable);

        return ResponseEntity.ok(codes);
    }

    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<InviteCodeResponseDTO>> searchCodes(
            @RequestParam String term,
            @PageableDefault(size = 20) Pageable pageable) {

        log.debug("🔍 Admin buscando códigos con término: {}", term);

        Page<InviteCodeResponseDTO> codes = inviteCodeService.searchCodes(term, pageable);

        return ResponseEntity.ok(codes);
    }
}