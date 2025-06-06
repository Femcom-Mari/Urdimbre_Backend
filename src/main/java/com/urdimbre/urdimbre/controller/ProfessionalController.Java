package com.urdimbre.urdimbre.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.dto.professional.ProfessionalRequestDTO;
import com.urdimbre.urdimbre.dto.professional.ProfessionalResponseDTO;
import com.urdimbre.urdimbre.service.professional.ProfessionalService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/professionals")
@RequiredArgsConstructor
@Slf4j
public class ProfessionalController {

    private final ProfessionalService professionalService;

    @PostMapping
    public ResponseEntity<ProfessionalResponseDTO> createProfessional(
            @Valid @RequestBody ProfessionalRequestDTO dto) {
        try {
            ProfessionalResponseDTO created = professionalService.createProfessional(dto);
            return ResponseEntity.status(201).body(created);
        } catch (Exception e) {
            log.error("Error creating professional: {}", e.getMessage(), e);
            throw e;
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<ProfessionalResponseDTO> updateProfessional(
            @PathVariable Long id,
            @Valid @RequestBody ProfessionalRequestDTO dto) {
        try {
            ProfessionalResponseDTO updated = professionalService.updateProfessional(id, dto);
            return ResponseEntity.ok(updated);
        } catch (Exception e) {
            log.error("Error updating professional with ID {}: {}", id, e.getMessage(), e);
            throw e;
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<ProfessionalResponseDTO> getProfessional(@PathVariable Long id) {
        try {
            ProfessionalResponseDTO professional = professionalService.getProfessional(id);
            return ResponseEntity.ok(professional);
        } catch (Exception e) {
            log.error("Error getting professional with ID {}: {}", id, e.getMessage(), e);
            throw e;
        }
    }

    @GetMapping
    public ResponseEntity<List<ProfessionalResponseDTO>> getAllProfessionals() {
        try {
            List<ProfessionalResponseDTO> professionals = professionalService.getAllProfessionals();
            return ResponseEntity.ok(professionals);
        } catch (Exception e) {
            log.error("Error getting professionals: {}", e.getMessage(), e);
            throw e;
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteProfessional(@PathVariable Long id) {
        try {
            professionalService.deleteProfessional(id);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            log.error("Error deleting professional with ID {}: {}", id, e.getMessage(), e);
            throw e;
        }
    }
}