package com.urdimbre.urdimbre.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.service.professional.ProfessionalService;
import com.urdimbre.urdimbre.model.Professional;

import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/professional")
@CrossOrigin(origins = "*")
public class ProfessionalsController {

    private ProfessionalService professionalService;

    public ProfessionalsController(ProfessionalService professionalService) {
        this.professionalService = professionalService;
    }

    @GetMapping
    public List<Professional> getAll() {
        return professionalService.getAllProfessionals();
    }
}
