package com.urdimbre.urdimbre.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Data
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CheckAvailabilityResponseDTO {
    private boolean available;
    private String message;

    public static CheckAvailabilityResponseDTO available(String message) {
        return CheckAvailabilityResponseDTO.builder()
                .available(true)
                .message(message)
                .build();
    }

    public static CheckAvailabilityResponseDTO notAvailable(String message) {
        return CheckAvailabilityResponseDTO.builder()
                .available(false)
                .message(message)
                .build();
    }

    public static CheckAvailabilityResponseDTO error(String message) {
        return CheckAvailabilityResponseDTO.builder()
                .available(false)
                .message(message)
                .build();
    }
}