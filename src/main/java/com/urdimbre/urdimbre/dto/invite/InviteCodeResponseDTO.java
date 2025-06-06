package com.urdimbre.urdimbre.dto.invite;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InviteCodeResponseDTO {

    private Long id;
    private String code;
    private String description;
    private String status;
    private String statusDisplayName;
    private LocalDateTime expiresAt;
    private Integer maxUses;
    private Integer currentUses;
    private String createdBy;
    private String usedBy;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // ✅ CAMPOS CALCULADOS
    private boolean isValid;
    private boolean isExpired;
    private boolean isMaxUsesReached;
    private long hoursUntilExpiration;
    private int remainingUses;
}