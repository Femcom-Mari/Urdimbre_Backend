package com.urdimbre.urdimbre.service.invite;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.urdimbre.urdimbre.dto.invite.BulkInviteCodeRequestDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodeRequestDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodeResponseDTO;
import com.urdimbre.urdimbre.dto.invite.InviteCodeStatsDTO;
import com.urdimbre.urdimbre.model.InviteCode;

public interface InviteCodeService {

    Optional<InviteCode> findByCode(String code);

    InviteCodeResponseDTO generateCode(InviteCodeRequestDTO request);

    List<InviteCodeResponseDTO> generateBulkCodes(BulkInviteCodeRequestDTO request);

    boolean validateInviteCode(String code);

    InviteCode useInviteCode(String code, String usedBy);

    Page<InviteCodeResponseDTO> getUserCodes(Pageable pageable);

    Page<InviteCodeResponseDTO> getAllCodes(Pageable pageable);

    InviteCodeStatsDTO getStatistics();

    InviteCodeResponseDTO revokeCode(Long id);

    int manualCleanup();

    Page<InviteCodeResponseDTO> getCodesByStatus(String status, Pageable pageable);

    Page<InviteCodeResponseDTO> getMostUsedCodes(Pageable pageable);

    Page<InviteCodeResponseDTO> searchCodes(String searchTerm, Pageable pageable);
}