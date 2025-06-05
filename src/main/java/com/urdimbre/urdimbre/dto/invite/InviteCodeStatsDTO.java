package com.urdimbre.urdimbre.dto.invite;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InviteCodeStatsDTO {

    private long totalCodes;
    private long activeCodes;
    private long expiredCodes;
    private long exhaustedCodes;
    private long revokedCodes;
    private long totalUses;
    private double averageUsesPerCode;
}