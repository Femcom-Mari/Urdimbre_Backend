package com.urdimbre.urdimbre.model;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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

    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 50, message = "El nombre no puede exceder los 50 caracteres")
    @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\\s]+$", message = "El nombre solo puede contener letras y espacios")
    private String firstName;

    @NotBlank(message = "El apellido es obligatorio")
    @Size(max = 50, message = "El apellido no puede exceder los 50 caracteres")
    @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\\s]+$", message = "El apellido solo puede contener letras y espacios")
    private String lastName;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "professional_pronouns", joinColumns = @JoinColumn(name = "professional_id"))
    @Column(name = "pronoun")
    @NotEmpty(message = "Al menos un pronombre es obligatorio")
    @Builder.Default
    private Set<Pronoun> pronouns = new HashSet<>();

    @Size(max = 100, message = "El título no puede exceder los 100 caracteres")
    private String title;

    @Size(max = 300, message = "La biografía no puede exceder los 300 caracteres")
    private String bio;

    @Pattern(regexp = "^\\+?[0-9\\-\\s]{7,20}$", message = "El formato del número de teléfono es inválido")
    private String phone;

    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El formato del email es inválido")
    private String email;

    @Size(max = 100, message = "La ubicación no puede exceder los 100 caracteres")
    private String location;

    @Size(max = 255, message = "La URL de la imagen de perfil no puede exceder los 255 caracteres")
    @Pattern(regexp = "^(https?://)?[\\w.-]+\\.[a-zA-Z]{2,}(/.*)?$", message = "El formato de la URL de la imagen de perfil es inválido")
    private String profileImageUrl;

    @Size(max = 255, message = "La URL no puede exceder los 255 caracteres")
    @Pattern(regexp = "^(https?://)?[\\w.-]+\\.[a-zA-Z]{2,}(/.*)?$", message = "El formato de la URL1 es inválido")
    private String url1;

    @Size(max = 255, message = "La URL no puede exceder los 255 caracteres")
    @Pattern(regexp = "^(https?://)?[\\w.-]+\\.[a-zA-Z]{2,}(/.*)?$", message = "El formato de la URL2 es inválido")
    private String url2;

    @Size(max = 255, message = "La URL no puede exceder los 255 caracteres")
    @Pattern(regexp = "^(https?://)?[\\w.-]+\\.[a-zA-Z]{2,}(/.*)?$", message = "El formato de la URL3 es inválido")
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
        ACTIVE("Activo"),
        INACTIVE("Inactivo"),
        DELETED("Eliminado");

        private final String displayValue;

        Status(String displayValue) {
            this.displayValue = displayValue;
        }

        public String getDisplayValue() {
            return displayValue;
        }
    }

    public enum Pronoun {
        ELLE("Elle"),
        ELLA("Ella"),
        EL("El");

        private final String displayValue;

        Pronoun(String displayValue) {
            this.displayValue = displayValue;
        }

        public String getDisplayValue() {
            return displayValue;
        }
    }
}