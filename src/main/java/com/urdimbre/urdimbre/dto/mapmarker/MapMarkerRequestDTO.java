package com.urdimbre.urdimbre.dto.mapmarker;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MapMarkerRequestDTO {
    private String title;
    private String description;
    private double latitude;
    private double longitude;
    private String iconUrl;
}
