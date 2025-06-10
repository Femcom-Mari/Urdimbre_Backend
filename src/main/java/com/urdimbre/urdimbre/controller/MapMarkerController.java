package com.urdimbre.urdimbre.controller;

import com.urdimbre.urdimbre.dto.mapmarker.MapMarkerRequestDTO;
import com.urdimbre.urdimbre.dto.mapmarker.MapMarkerResponseDTO;
import com.urdimbre.urdimbre.service.mapmarker.MapMarkerService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/map-markers")
@RequiredArgsConstructor
public class MapMarkerController {

    private final MapMarkerService service;

    @GetMapping
    public ResponseEntity<List<MapMarkerResponseDTO>> getAllMarkers() {
        return ResponseEntity.ok(service.getAllMarkers());
    }

    @PostMapping
    public ResponseEntity<MapMarkerResponseDTO> createMarker(@RequestBody MapMarkerRequestDTO dto) {
        return ResponseEntity.ok(service.createMarker(dto));
    }

    @PostMapping("/{id}/vote")
    public ResponseEntity<MapMarkerResponseDTO> vote(
            @PathVariable Long id,
            @RequestParam(required = false, defaultValue = "false") boolean like,
            @RequestParam(required = false, defaultValue = "false") boolean conflict) {
        return ResponseEntity.ok(service.vote(id, like, conflict));
    }
}
