package com.urdimbre.urdimbre.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.urdimbre.urdimbre.repository.ProfessionalsRepository;
import org.springframework.web.bind.annotation.GetMapping;

import com.urdimbre.urdimbre.model.Professional;

import java.util.List;

@RestController
@RequestMapping("/api/professional")
@CrossOrigin(origins = "*")
public class ProfessionalsController {

    @Autowired
    private ProfessionalsRepository professionalsRepository;

    @GetMapping
    public List<Professional> getAll() {
        return professionalsRepository.findAll();
    }
}
