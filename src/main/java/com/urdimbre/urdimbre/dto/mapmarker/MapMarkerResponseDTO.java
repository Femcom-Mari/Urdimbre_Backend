package com.urdimbre.urdimbre.dto.mapmarker;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MapMarkerResponseDTO {
    private Long id;
    private String title;
    private String description;
    private double latitude;
    private double longitude;
    private String iconUrl;
    private int likes;
    private int dislikes;
    private int conflicts;
    private String safetyStatus; // "safe", "unsafe", "conflict", "unknown"
}