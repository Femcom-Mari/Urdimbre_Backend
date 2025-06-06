package com.urdimbre.urdimbre.service.professional;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.urdimbre.urdimbre.dto.professional.ProfessionalRequestDTO;
import com.urdimbre.urdimbre.dto.professional.ProfessionalResponseDTO;
import com.urdimbre.urdimbre.model.Professional;
import com.urdimbre.urdimbre.repository.ProfessionalRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ProfessionalServiceImpl implements ProfessionalService {

    private final ProfessionalRepository professionalRepository;

    @Override
    @Transactional
    public ProfessionalResponseDTO createProfessional(ProfessionalRequestDTO dto) {
        Professional professional = mapToEntity(dto);
        Professional saved = professionalRepository.save(professional);
        return mapToResponseDTO(saved);
    }

    @Override
    @Transactional
    public ProfessionalResponseDTO updateProfessional(Long id, ProfessionalRequestDTO dto) {
        Professional professional = professionalRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Professional not found"));

        professional.setFirstName(dto.getFirstName());
        professional.setLastName(dto.getLastName());
        professional.setPronouns(mapPronouns(dto.getPronouns()));
        professional.setTitle(dto.getTitle());
        professional.setBio(dto.getBio());
        professional.setPhone(dto.getPhone());
        professional.setEmail(dto.getEmail());
        professional.setLocation(dto.getLocation());
        professional.setProfileImageUrl(dto.getProfileImageUrl());
        professional.setUrl1(dto.getUrl1());
        professional.setUrl2(dto.getUrl2());
        professional.setUrl3(dto.getUrl3());

        Professional updated = professionalRepository.save(professional);
        return mapToResponseDTO(updated);
    }

    @Override
    public ProfessionalResponseDTO getProfessional(Long id) {
        Professional professional = professionalRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Professional not found"));
        return mapToResponseDTO(professional);
    }

    @Override
    public List<ProfessionalResponseDTO> getAllProfessionals() {
        return professionalRepository.findAll().stream()
                .map(this::mapToResponseDTO)
                .toList();
    }

    @Override
    @Transactional
    public void deleteProfessional(Long id) {
        if (!professionalRepository.existsById(id)) {
            throw new RuntimeException("Professional not found");
        }
        professionalRepository.deleteById(id);
    }

    // --- Mapping methods ---

    private Professional mapToEntity(ProfessionalRequestDTO dto) {
        return Professional.builder()
                .firstName(dto.getFirstName())
                .lastName(dto.getLastName())
                .pronouns(mapPronouns(dto.getPronouns()))
                .title(dto.getTitle())
                .bio(dto.getBio())
                .phone(dto.getPhone())
                .email(dto.getEmail())
                .location(dto.getLocation())
                .profileImageUrl(dto.getProfileImageUrl())
                .url1(dto.getUrl1())
                .url2(dto.getUrl2())
                .url3(dto.getUrl3())
                .build();
    }

    private Set<Professional.Pronoun> mapPronouns(Set<String> pronouns) {
        return pronouns.stream().map(s -> {
            try {
                return mapStringToPronoun(s);
            } catch (IllegalArgumentException e) {
                throw new RuntimeException("Pronombre inválido: " + s +
                        ". Valores válidos: Elle, Ella, El");
            }
        }).collect(Collectors.toSet());
    }

    private Professional.Pronoun mapStringToPronoun(String pronounString) {
        // Intentar mapear por display value (Elle, Ella, El)
        for (Professional.Pronoun pronoun : Professional.Pronoun.values()) {
            if (pronoun.getDisplayValue().equalsIgnoreCase(pronounString)) {
                return pronoun;
            }
        }

        // Fallback: intentar mapear por enum name (ELLE, ELLA, EL)
        try {
            return Professional.Pronoun.valueOf(pronounString.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Pronombre no válido: " + pronounString +
                    ". Valores válidos: Elle, Ella, El");
        }
    }

    private ProfessionalResponseDTO mapToResponseDTO(Professional professional) {
        ProfessionalResponseDTO dto = new ProfessionalResponseDTO();
        dto.setId(professional.getId());
        dto.setFirstName(professional.getFirstName());
        dto.setLastName(professional.getLastName());

        // Mapear usando display values
        dto.setPronouns(
                professional.getPronouns().stream()
                        .map(Professional.Pronoun::getDisplayValue)
                        .collect(Collectors.toSet()));

        dto.setTitle(professional.getTitle());
        dto.setBio(professional.getBio());
        dto.setPhone(professional.getPhone());
        dto.setEmail(professional.getEmail());
        dto.setLocation(professional.getLocation());
        dto.setProfileImageUrl(professional.getProfileImageUrl());
        dto.setUrl1(professional.getUrl1());
        dto.setUrl2(professional.getUrl2());
        dto.setUrl3(professional.getUrl3());
        dto.setStatus(professional.getStatus().name());
        dto.setCreatedAt(professional.getCreatedAt());
        dto.setUpdatedAt(professional.getUpdatedAt());
        return dto;
    }
}