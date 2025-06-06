package com.urdimbre.urdimbre.service.invite;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.urdimbre.urdimbre.dto.invite.BulkInviteCodeRequestDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodeRequestDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodeResponseDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodeStatsDTO;
import com.urdimbre.urdimbre.model.InviteCode;

/**
 * 🎟️ Servicio para gestión de códigos de invitación
 */
public interface InviteCodeService {

    /**
     * 🎟️ Generar nuevo código de invitación individual
     */
    InviteCodeResponseDTO generateCode(InviteCodeRequestDTO request);

    /**
     * 🎯 Generar múltiples códigos en lote
     */
    List<InviteCodeResponseDTO> generateBulkCodes(BulkInviteCodeRequestDTO request);

    /**
     * ✅ Validar si un código de invitación es válido
     */
    boolean validateInviteCode(String code);

    /**
     * 🎫 Usar código de invitación (marcar como usado)
     */
    InviteCode useInviteCode(String code, String usedBy);

    /**
     * 📋 Obtener códigos creados por el usuario actual
     */
    Page<InviteCodeResponseDTO> getUserCodes(Pageable pageable);

    /**
     * 📋 Obtener todos los códigos (solo administradores)
     */
    Page<InviteCodeResponseDTO> getAllCodes(Pageable pageable);

    /**
     * 📊 Obtener estadísticas generales de códigos
     */
    InviteCodeStatsDTO getStatistics();

    /**
     * 🚫 Revocar código de invitación
     */
    InviteCodeResponseDTO revokeCode(Long id);

    /**
     * 🧹 Ejecutar limpieza manual de códigos expirados
     */
    int manualCleanup();

    /**
     * 📈 Obtener códigos por estado
     */
    Page<InviteCodeResponseDTO> getCodesByStatus(String status, Pageable pageable);

    /**
     * 📈 Obtener códigos más usados
     */
    Page<InviteCodeResponseDTO> getMostUsedCodes(Pageable pageable);

    /**
     * 🔍 Buscar códigos por criterios
     */
    Page<InviteCodeResponseDTO> searchCodes(String searchTerm, Pageable pageable);
}