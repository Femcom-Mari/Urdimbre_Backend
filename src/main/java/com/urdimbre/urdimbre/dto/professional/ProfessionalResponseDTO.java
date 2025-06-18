package com.urdimbre.urdimbre.dto.professional;


import java.util.Set;

import com.urdimbre.urdimbre.model.CommunityStatus;
import lombok.Data;

@Data
public class ProfessionalResponseDTO {

    private Long id;
    private String city;
    private String name;
    private Set<String> pronouns;
    private String description;
    private String phone;
    private String email;
    private String website;
    private String socialMedia;
    private String town;
    private String activities;
    private String price;
    private CommunityStatus communityStatus;
}

