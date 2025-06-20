package com.urdimbre.urdimbre.model;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "invite_codes", indexes = {
        @Index(name = "idx_invite_code", columnList = "code"),
        @Index(name = "idx_invite_status", columnList = "status"),
        @Index(name = "idx_invite_expires_at", columnList = "expiresAt"),
        @Index(name = "idx_invite_created_by", columnList = "createdBy")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class InviteCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "code", nullable = false, unique = true, length = 50)
    private String code;

    @Column(name = "description", length = 255)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    @Builder.Default
    private InviteStatus status = InviteStatus.ACTIVE;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "max_uses")
    private Integer maxUses;

    @Column(name = "current_uses")
    @Builder.Default
    private Integer currentUses = 0;

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "used_by")
    private String usedBy; // Último usuario que lo usó

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    public boolean isValid() {
        return status == InviteStatus.ACTIVE
                && expiresAt.isAfter(LocalDateTime.now())
                && (maxUses == null || currentUses < maxUses);
    }

    public boolean isExpired() {
        return expiresAt.isBefore(LocalDateTime.now());
    }

    public boolean isMaxUsesReached() {
        return maxUses != null && currentUses >= maxUses;
    }

    public void incrementUses(String usedByUser) {
        this.currentUses++;
        this.usedBy = usedByUser;

        // Si se alcanzó el máximo, marcar como usado
        if (maxUses != null && currentUses >= maxUses) {
            this.status = InviteStatus.EXHAUSTED;
        }
    }

    public void revoke() {
        this.status = InviteStatus.REVOKED;
    }

    public void markAsExpired() {
        this.status = InviteStatus.EXPIRED;
    }

    public enum InviteStatus {
        ACTIVE("Activo"),
        EXPIRED("Expirado"),
        EXHAUSTED("Sin usos disponibles"),
        REVOKED("Revocado por administrador"),
        DISABLED("Deshabilitado");

        private final String displayName;

        InviteStatus(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }
}