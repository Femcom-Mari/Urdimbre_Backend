package com.urdimbre.urdimbre.dto.professional;

import java.util.Set;

import com.urdimbre.urdimbre.model.CommunityStatus;
import com.urdimbre.urdimbre.model.Pronouns;
import jakarta.validation.constraints.*;

import lombok.Data;

@Data
public class ProfessionalRequestDTO {

    @NotBlank(message = "City is required")
    @Size(max = 100)
    private String city;

    @NotBlank(message = "Name is required")
    @Size(max = 100)
    private String name;

    @NotNull(message = "Pronouns are required")
     private Set<Pronouns> pronouns;

    @Size(max = 1000)
    private String description;

    @Pattern(regexp = "^\\+?[0-9\\-\\s()]{7,20}$", message = "Invalid phone number format")
    private String phone;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @Size(max = 255)
    @Pattern(regexp = "^(https?://)?[\\w.-]+\\.[a-zA-Z]{2,}.*$", message = "Invalid website URL format")
    private String website;

    @Size(max = 255)
    private String socialMedia;

    @Size(max = 100)
    private String town;

    @Size(max = 500)
    private String activities;

    @Size(max = 100)
    private String price;

    @NotNull(message = "Community status is required")
    private CommunityStatus communityStatus;
}
