package com.urdimbre.urdimbre.service.professional;

import com.urdimbre.urdimbre.dto.professional.ProfessionalRequestDTO;
import com.urdimbre.urdimbre.dto.professional.ProfessionalResponseDTO;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface ProfessionalService {


    ProfessionalResponseDTO createProfessional(ProfessionalRequestDTO dto);

    ProfessionalResponseDTO updateProfessional(Long id, ProfessionalRequestDTO dto);

    ProfessionalResponseDTO getProfessional(Long id);

    List<ProfessionalResponseDTO> getAllProfessionals();

    void deleteProfessional(Long id);
}



