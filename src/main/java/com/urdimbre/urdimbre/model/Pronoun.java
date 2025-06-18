// package com.urdimbre.urdimbre.model;

// import com.fasterxml.jackson.annotation.JsonValue;

//     public enum Pronoun {
//         ELLE("Elle"),
//         ELLA("Ella"),
//         EL("El");

//         private final String displayValue;

//         Pronoun(String displayValue) {
//             this.displayValue = displayValue;
//         }

//         @JsonValue
//         public String getDisplayValue() {
//             return displayValue;
//         }

//         public static Pronoun fromDisplayValue(String displayValue) {
//             for (Pronoun pronoun : values()) {
//                 if (pronoun.displayValue.equals(displayValue)) {
//                     return pronoun;
//                 }
//             }
//             throw new IllegalArgumentException("Pronombre inválido: " + displayValue +
//                     ". Valores válidos: Elle, Ella, El");
//         }

//         @Override
//         public String toString() {
//             return displayValue;
//         }
//     }