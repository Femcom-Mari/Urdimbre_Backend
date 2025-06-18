package com.urdimbre.urdimbre.model;

import java.util.HashSet;
import java.util.Set;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;

import lombok.*;

@Entity
@Table(name = "professionals")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class Professional {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "City is required")
    @Size(max = 100)
    private String city;

    @NotBlank(message = "Name is required")
    @Size(max = 100)
    private String name;

    @ElementCollection(targetClass = Pronoun.class, fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "professional_pronouns", joinColumns = @JoinColumn(name = "professional_id"))
    @Column(name = "pronoun")
    @NotEmpty(message = "You must select at least one pronoun")
    @Builder.Default
    private Set<Pronoun> pronouns = new HashSet<>();


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

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "community_status", length = 20, nullable = false)
    private CommunityStatus communityStatus;

    

}
