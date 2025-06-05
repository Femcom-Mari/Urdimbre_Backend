package com.urdimbre.urdimbre.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

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

    @NotBlank(message = "First name is required")
    @Size(max = 50, message = "First name must not exceed 50 characters")
    @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\\s]+$", message = "First name can only contain letters and spaces")
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(max = 50, message = "Last name must not exceed 50 characters")
    @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\\s]+$", message = "Last name can only contain letters and spaces")
    private String lastName;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "professional_pronouns", joinColumns = @JoinColumn(name = "professional_id"))
    @Column(name = "pronoun")
    @NotEmpty(message = "At least one pronoun is required")
    private Set<Pronoun> pronouns = new HashSet<>();

    @Size(max = 100, message = "Title must not exceed 100 characters")
    private String title;

    @Size(max = 300, message = "Bio must not exceed 300 characters")
    private String bio;

    @Pattern(regexp = "^\\+?[0-9\\-\\s]{7,20}$", message = "Phone number format is invalid")
    private String phone;

    @NotBlank(message = "Email is required")
    @Email(message = "Email format is invalid")
    private String email;

    @Size(max = 100, message = "Location must not exceed 100 characters")
    private String location;

    @Size(max = 255, message = "Profile image URL must not exceed 255 characters")
    @Pattern(regexp = "^(https?://)?[\\w.-]+(?:\\.[\\w\\.-]+)+[/#?]?.*$", message = "Profile image URL format is invalid")
    private String profileImageUrl;

    @Size(max = 255, message = "URL must not exceed 255 characters")
    @Pattern(regexp = "^(https?://)?[\\w.-]+(?:\\.[\\w\\.-]+)+[/#?]?.*$", message = "URL1 format is invalid")
    private String url1;

    @Size(max = 255, message = "URL must not exceed 255 characters")
    @Pattern(regexp = "^(https?://)?[\\w.-]+(?:\\.[\\w\\.-]+)+[/#?]?.*$", message = "URL2 format is invalid")
    private String url2;

    @Size(max = 255, message = "URL must not exceed 255 characters")
    @Pattern(regexp = "^(https?://)?[\\w.-]+(?:\\.[\\w\\.-]+)+[/#?]?.*$", message = "URL3 format is invalid")
    private String url3;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private Status status = Status.ACTIVE;

    public enum Status {
        ACTIVE, INACTIVE, DELETED
    }

    public enum Pronoun {
        SHE, // Ella
        HE, // Él
        THEY // Elle
    }
}