package com.urdimbre.urdimbre.service.mapmarker;

import com.urdimbre.urdimbre.dto.mapmarker.MapMarkerRequestDTO;
import com.urdimbre.urdimbre.dto.mapmarker.MapMarkerResponseDTO;

import java.util.List;

public interface MapMarkerService {
    List<MapMarkerResponseDTO> getAllMarkers();

    MapMarkerResponseDTO createMarker(MapMarkerRequestDTO dto);

    MapMarkerResponseDTO vote(Long id, boolean like, boolean conflict);
    // Puedes añadir más métodos: update, delete, findById, etc.
}
