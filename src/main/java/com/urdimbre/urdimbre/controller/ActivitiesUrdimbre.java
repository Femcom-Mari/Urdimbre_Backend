package com.urdimbre.urdimbre.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
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
}
