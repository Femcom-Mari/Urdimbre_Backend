package com.urdimbre.urdimbre.dto.professional;

import lombok.Data;
import java.time.LocalDateTime;
import java.util.Set;

@Data
public class ProfessionalResponseDTO {
    private Long id;
    private String firstName;
    private String lastName;
    private Set<String> pronouns;
    private String title;
    private String bio;
    private String phone;
    private String email;
    private String location;
    private String profileImageUrl;
    private String url1;
    private String url2;
    private String url3;
    private String status;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
