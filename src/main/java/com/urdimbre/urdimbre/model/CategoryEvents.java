package com.urdimbre.urdimbre.model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum CategoryEvents {
    REVINDICATIVOS("Reivindicativos"),
    OCIO("Ocio"),
    ARTISITICOS("Artisticos"),
    DEPORTIVOS("Deportivos"),
    MIXTOS("Mixtos"),
    NOMIXTOS("No mixtos");


    
        private final String displayValue;

        CategoryEvents(String displayValue) {
            this.displayValue = displayValue;
        }

        @JsonValue
        public String getDisplayValue() {
            return displayValue;
        }

        public static CategoryEvents fromDisplayValue(String displayValue) {
            for (CategoryEvents categoryEvent : values()) {
                if (categoryEvent.displayValue.equals(displayValue)) {
                    return categoryEvent;
                }
            }
            throw new IllegalArgumentException("Categoría inválida: " + displayValue +
                    ". Valores válidos: Reivindicativos, Ocio, Artisticos, Deportivos, Mixtos, No mixtos");
        }

        @Override
        public String toString() {
            return displayValue;
        }
    }

