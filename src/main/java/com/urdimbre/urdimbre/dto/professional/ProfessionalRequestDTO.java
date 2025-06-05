package com.urdimbre.urdimbre.dto.professional;

import jakarta.validation.constraints.*;
import lombok.Data;
import java.util.Set;

@Data
public class ProfessionalRequestDTO {

    @NotBlank(message = "First name is required")
    @Size(max = 50)
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(max = 50)
    private String lastName;

    @NotEmpty(message = "At least one pronoun is required")
    private Set<String> pronouns; // Enum values as String: SHE, HE, THEY

    @Size(max = 100)
    private String title;

    @Size(max = 300)
    private String bio;

    @Pattern(regexp = "^\\+?[0-9\\-\\s]{7,20}$", message = "Phone number format is invalid")
    private String phone;

    @NotBlank
    @Email
    private String email;

    @Size(max = 100)
    private String location;

    @Size(max = 255)
    private String profileImageUrl;

    @Size(max = 255)
    private String url1;

    @Size(max = 255)
    private String url2;

    @Size(max = 255)
    private String url3;
}
