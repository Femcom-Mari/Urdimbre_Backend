package com.urdimbre.urdimbre.service.mapmarker;

import com.urdimbre.urdimbre.dto.mapmarker.MapMarkerRequestDTO;
import com.urdimbre.urdimbre.dto.mapmarker.MapMarkerResponseDTO;
import com.urdimbre.urdimbre.model.MapMarker;
import com.urdimbre.urdimbre.repository.MapMarkerRepository;
// import com.urdimbre.urdimbre.service.MapMarkerService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class MapMarkerServiceImpl implements MapMarkerService {

    private final MapMarkerRepository repository;

    @Override
    public List<MapMarkerResponseDTO> getAllMarkers() {
        return repository.findAll().stream()
                .map(this::toResponseDTO)
                .collect(Collectors.toList());
    }

    @Override
    public MapMarkerResponseDTO createMarker(MapMarkerRequestDTO dto) {
        MapMarker marker = MapMarker.builder()
                .title(dto.getTitle())
                .description(dto.getDescription())
                .latitude(dto.getLatitude())
                .longitude(dto.getLongitude())
                .iconUrl(dto.getIconUrl())
                .likes(0)
                .dislikes(0)
                .conflicts(0)
                .build();
        return toResponseDTO(repository.save(marker));
    }

    @Override
    public MapMarkerResponseDTO vote(Long id, boolean like, boolean conflict) {
        MapMarker marker = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Marker not found"));
        if (conflict) {
            marker.setConflicts(marker.getConflicts() + 1);
        } else if (like) {
            marker.setLikes(marker.getLikes() + 1);
        } else {
            marker.setDislikes(marker.getDislikes() + 1);
        }
        return toResponseDTO(repository.save(marker));
    }

    private MapMarkerResponseDTO toResponseDTO(MapMarker marker) {
        return MapMarkerResponseDTO.builder()
                .id(marker.getId())
                .title(marker.getTitle())
                .description(marker.getDescription())
                .latitude(marker.getLatitude())
                .longitude(marker.getLongitude())
                .iconUrl(marker.getIconUrl())
                .likes(marker.getLikes())
                .dislikes(marker.getDislikes())
                .conflicts(marker.getConflicts())
                .safetyStatus(marker.getSafetyStatusValue())
                .build();
    }
}