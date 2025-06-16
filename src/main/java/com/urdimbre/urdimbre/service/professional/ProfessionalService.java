package com.urdimbre.urdimbre.service.professional;

import com.urdimbre.urdimbre.model.Professional;
import org.springframework.stereotype.Service;
import com.urdimbre.urdimbre.repository.ProfessionalsRepository;

import java.util.List;

@Service
public class ProfessionalService {
    private final ProfessionalsRepository professionalsRepository;

    public ProfessionalService(ProfessionalsRepository professionalsRepository) {
        this.professionalsRepository = professionalsRepository;
    }

    public List<Professional> getAllProfessionals() {
        return professionalsRepository.findAll();
    }
}
