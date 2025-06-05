package com.urdimbre.urdimbre.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.urdimbre.urdimbre.dto.ActivitiesUrdimbre.ActivitiesUrdimbreRequestDTO;
import com.urdimbre.urdimbre.dto.ActivitiesUrdimbre.ActivitiesUrdimbreResponseDTO;
import com.urdimbre.urdimbre.service.ActivitiesUrdimbre.ActivitiesUrdimbreService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
@RequestMapping("/api/activities")
public class ActivitiesUrdimbre {

    private ActivitiesUrdimbreService activitiesUrdimbreService;

    @PostMapping("/create")
    public ResponseEntity<ActivitiesUrdimbreResponseDTO> createActivitiesUrdimbre(
            @Valid @RequestBody ActivitiesUrdimbreRequestDTO dto) {
        ActivitiesUrdimbreResponseDTO createdActivity = activitiesUrdimbreService.createActivitiesUrdimbre(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdActivity);
    }

        @GetMapping("/category/{category}")
    public ResponseEntity<List<ActivitiesUrdimbreResponseDTO>> getActivitiesByCategory(
            @PathVariable String category,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "15") int size) {
        List<ActivitiesUrdimbreResponseDTO> activities = activitiesUrdimbreService.getActivitiesByCategory(category);
        return ResponseEntity.ok(activities);
    }
}
