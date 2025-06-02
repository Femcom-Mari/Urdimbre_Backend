package com.urdimbre.urdimbre.model;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.fasterxml.jackson.annotation.JsonValue;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(name = "full_name")
    private String fullName;

    @Column(columnDefinition = "TEXT")
    private String biography;

    private String location;

    @Column(name = "profile_image_url")
    private String profileImageUrl;

    // ✅ ENUM CORREGIDO CON VALORES VÁLIDOS EN JAVA
    @Enumerated(EnumType.STRING)
    private Pronoun pronouns;

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private UserStatus status = UserStatus.ACTIVE;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    public boolean isEnabled() {
        return this.status == UserStatus.ACTIVE;
    }

    // ✅ ENUM CORREGIDO: Nombres técnicos con valores de presentación
    public enum Pronoun {
        ELLE("Elle"),
        ELLA("Ella"),
        EL("El");

        private final String displayValue;

        Pronoun(String displayValue) {
            this.displayValue = displayValue;
        }

        @JsonValue // ✅ Esto hace que Jackson serialice el displayValue
        public String getDisplayValue() {
            return displayValue;
        }

        // ✅ Método para buscar por valor de display
        public static Pronoun fromDisplayValue(String displayValue) {
            for (Pronoun pronoun : values()) {
                if (pronoun.displayValue.equals(displayValue)) {
                    return pronoun;
                }
            }
            throw new IllegalArgumentException("Pronombre inválido: " + displayValue +
                    ". Valores válidos: Elle, Ella, El");
        }

        @Override
        public String toString() {
            return displayValue;
        }
    }

    public enum UserStatus {
        ACTIVE, INACTIVE, BANNED, DELETED
    }
}
