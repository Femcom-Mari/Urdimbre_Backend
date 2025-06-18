package com.urdimbre.urdimbre.service.professional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.urdimbre.urdimbre.dto.professional.ProfessionalRequestDTO;
import com.urdimbre.urdimbre.dto.professional.ProfessionalResponseDTO;
import com.urdimbre.urdimbre.model.Professional;
import com.urdimbre.urdimbre.model.Pronoun;
import com.urdimbre.urdimbre.repository.ProfessionalRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ProfessionalServiceImpl implements ProfessionalService {

    private final ProfessionalRepository professionalRepository;

    @Override
    @Transactional
    public ProfessionalResponseDTO createProfessional(ProfessionalRequestDTO dto) {
        Professional professional = new Professional();
        applyDtoToProfessional(dto, professional);
        Professional saved = professionalRepository.save(professional);
        return mapToResponseDTO(saved);
    }

    @Override
    @Transactional
    public ProfessionalResponseDTO updateProfessional(Long id, ProfessionalRequestDTO dto) {
        Professional professional = professionalRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Professional not found"));

        applyDtoToProfessional(dto, professional);
        Professional updated = professionalRepository.save(professional);
        return mapToResponseDTO(updated);
    }

    @Override
    public ProfessionalResponseDTO getProfessional(Long id) {
        return professionalRepository.findById(id)
                .map(this::mapToResponseDTO)
                .orElseThrow(() -> new RuntimeException("Professional not found"));
    }

    @Override
    public List<ProfessionalResponseDTO> getAllProfessionals() {
        return professionalRepository.findAll().stream()
                .map(this::mapToResponseDTO)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public void deleteProfessional(Long id) {
        if (!professionalRepository.existsById(id)) {
            throw new RuntimeException("Professional not found");
        }
        professionalRepository.deleteById(id);
    }


    private void applyDtoToProfessional(ProfessionalRequestDTO dto, Professional professional) {
        professional.setName(dto.getName());
        professional.setCity(dto.getCity());
        professional.setDescription(dto.getDescription());
        professional.setPhone(dto.getPhone());
        professional.setEmail(dto.getEmail());
        professional.setWebsite(dto.getWebsite());
        professional.setSocialMedia(dto.getSocialMedia());
        professional.setTown(dto.getTown());
        professional.setActivities(dto.getActivities());
        professional.setPrice(dto.getPrice());
        professional.setCommunityStatus(dto.getCommunityStatus());

        if (dto.getPronouns() != null && !dto.getPronouns().isEmpty()) {
            professional.setPronouns(mapPronouns(dto.getPronouns()));
        } else {
            professional.setPronouns(new HashSet<>()); // evita nulls
        }
    }

    private Set<Pronoun> mapPronouns(Set<String> pronounStrings) {
        Set<Pronoun> pronouns = new HashSet<>();
        for (String str : pronounStrings) {
            try {
                pronouns.add(Pronoun.fromDisplayValue(str));
            } catch (IllegalArgumentException e) {
                throw new RuntimeException("Pronombre inválido: " + str +
                        ". Valores válidos: Elle, Ella, El");
            }
        }
        return pronouns;
    }

    private ProfessionalResponseDTO mapToResponseDTO(Professional professional) {
        ProfessionalResponseDTO dto = new ProfessionalResponseDTO();
        dto.setId(professional.getId());
        dto.setName(professional.getName());
        dto.setCity(professional.getCity());
        if (professional.getPronouns() != null && !professional.getPronouns().isEmpty()) {
            Set<String> pronounStrings = professional.getPronouns().stream()
                    .map(Pronoun::getDisplayValue)
                    .collect(Collectors.toSet());
            dto.setPronouns(pronounStrings);
        }
        dto.setDescription(professional.getDescription());
        dto.setPhone(professional.getPhone());
        dto.setEmail(professional.getEmail());
        dto.setWebsite(professional.getWebsite());
        dto.setSocialMedia(professional.getSocialMedia());
        dto.setTown(professional.getTown());
        dto.setActivities(professional.getActivities());
        dto.setPrice(professional.getPrice());
        dto.setCommunityStatus(professional.getCommunityStatus());
        return dto;
    }
}

