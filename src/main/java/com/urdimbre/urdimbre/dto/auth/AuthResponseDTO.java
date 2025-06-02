package com.urdimbre.urdimbre.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponseDTO {
    private String accessToken;
    private String refreshToken;
    private String username;
    private String email;
    private String fullName;

    @Builder.Default
    private String tokenType = "Bearer";
}