package com.urdimbre.urdimbre.model;

import jakarta.persistence.*;
import lombok.*;

/**
 * Entidad que representa un marcador geolocalizado en el mapa.
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MapMarker {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String title;
    private String description;
    private double latitude;
    private double longitude;
    private String iconUrl; // URL para icono personalizado

    private int likes; // votos positivos
    private int dislikes; // votos negativos
    private int conflicts; // reportes de conflicto

    /**
     * Enum para el estado de seguridad del espacio.
     */
    public enum SafetyStatus {
        SAFE("safe"), // verde
        UNSAFE("unsafe"), // rojo
        CONFLICT("conflict"), // naranja
        UNKNOWN("unknown"); // blanco

        private final String value;

        SafetyStatus(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Calcula el estado de seguridad del espacio.
     * 
     * @return SafetyStatus (SAFE, UNSAFE, CONFLICT, UNKNOWN)
     */
    public SafetyStatus getSafetyStatus() {
        int totalVotes = likes + dislikes + conflicts;
        if (totalVotes == 0) {
            return SafetyStatus.UNKNOWN; // blanco
        }
        if (conflicts > likes && conflicts > dislikes) {
            return SafetyStatus.CONFLICT; // naranja
        }
        double ratio = (double) likes / Math.max(1, likes + dislikes); // evitar división por cero
        if (ratio >= 0.7) {
            return SafetyStatus.SAFE; // verde
        }
        if (ratio <= 0.3) {
            return SafetyStatus.UNSAFE; // rojo
        }
        return SafetyStatus.UNKNOWN; // blanco si no se puede determinar
    }

    /**
     * Devuelve el estado de seguridad como string (para API/DTO).
     */
    @Transient
    public String getSafetyStatusValue() {
        return getSafetyStatus().toString();
    }
}
