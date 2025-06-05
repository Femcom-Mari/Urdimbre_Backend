package com.urdimbre.urdimbre.controller;

import com.urdimbre.urdimbre.dto.professional.ProfessionalRequestDTO;
import com.urdimbre.urdimbre.dto.professional.ProfessionalResponseDTO;
import com.urdimbre.urdimbre.service.professional.ProfessionalService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/professionals")
@RequiredArgsConstructor
public class ProfessionalController {

    private final ProfessionalService professionalService;

    @PostMapping
    public ResponseEntity<ProfessionalResponseDTO> createProfessional(
            @Valid @RequestBody ProfessionalRequestDTO dto) {
        ProfessionalResponseDTO created = professionalService.createProfessional(dto);
        return ResponseEntity.status(201).body(created);
    }

    @PutMapping("/{id}")
    public ResponseEntity<ProfessionalResponseDTO> updateProfessional(
            @PathVariable Long id,
            @Valid @RequestBody ProfessionalRequestDTO dto) {
        ProfessionalResponseDTO updated = professionalService.updateProfessional(id, dto);
        return ResponseEntity.ok(updated);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ProfessionalResponseDTO> getProfessional(@PathVariable Long id) {
        ProfessionalResponseDTO professional = professionalService.getProfessional(id);
        return ResponseEntity.ok(professional);
    }

    @GetMapping
    public ResponseEntity<List<ProfessionalResponseDTO>> getAllProfessionals() {
        List<ProfessionalResponseDTO> professionals = professionalService.getAllProfessionals();
        return ResponseEntity.ok(professionals);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteProfessional(@PathVariable Long id) {
        professionalService.deleteProfessional(id);
        return ResponseEntity.noContent().build();
    }
}