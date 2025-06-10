package com.urdimbre.urdimbre.util;

import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 🛡️ UTILIDAD DE SANITIZACIÓN HTML
 * Protege contra ataques XSS y injection de contenido malicioso
 */
public class HtmlSanitizer {

    private static final Logger logger = LoggerFactory.getLogger(HtmlSanitizer.class);

    // 🚫 PATRONES PELIGROSOS PRECOMPILADOS PARA PERFORMANCE
    private static final Pattern SCRIPT_PATTERN = Pattern.compile(
            "(?i)<script[^>]*>.*?</script>", Pattern.DOTALL);

    private static final Pattern STYLE_PATTERN = Pattern.compile(
            "(?i)<style[^>]*>.*?</style>", Pattern.DOTALL);

    private static final Pattern ALL_HTML_PATTERN = Pattern.compile(
            "<[^>]*>");

    private static final Pattern JAVASCRIPT_PATTERN = Pattern.compile(
            "(?i)javascript:", Pattern.CASE_INSENSITIVE);

    private static final Pattern VBSCRIPT_PATTERN = Pattern.compile(
            "(?i)vbscript:", Pattern.CASE_INSENSITIVE);

    private static final Pattern DATA_URL_PATTERN = Pattern.compile(
            "(?i)data:", Pattern.CASE_INSENSITIVE);

    // 🚨 EVENTOS JAVASCRIPT PELIGROSOS
    private static final Pattern DANGEROUS_EVENTS_PATTERN = Pattern.compile(
            "(?i)(on\\w+\\s*=|expression\\s*\\()", Pattern.CASE_INSENSITIVE);

    // 🔒 CARACTERES ESPECIALES PARA ENCODING
    private static final Pattern[] DANGEROUS_CHARS = {
            Pattern.compile("<", Pattern.LITERAL),
            Pattern.compile(">", Pattern.LITERAL),
            Pattern.compile("&", Pattern.LITERAL),
            Pattern.compile("\"", Pattern.LITERAL),
            Pattern.compile("'", Pattern.LITERAL)
    };

    private static final String[] SAFE_REPLACEMENTS = {
            "&lt;", "&gt;", "&amp;", "&quot;", "&#x27;"
    };

    private HtmlSanitizer() {
        // Utility class - no instances
    }

    /**
     * 🧹 Remover completamente todas las etiquetas HTML
     * Uso: campos de texto plano, usernames, emails
     */
    public static String stripAllTags(String input) {
        if (input == null) {
            return null;
        }

        if (input.trim().isEmpty()) {
            return input;
        }

        try {
            // 🔍 LOG PARA DETECTAR INTENTOS DE INYECCIÓN
            if (containsSuspiciousContent(input)) {
                logger.warn("🚨 Contenido sospechoso detectado y sanitizado: {}",
                        input.length() > 50 ? input.substring(0, 50) + "..." : input);
            }

            String sanitized = input;

            // 1️⃣ REMOVER SCRIPTS
            sanitized = SCRIPT_PATTERN.matcher(sanitized).replaceAll("");

            // 2️⃣ REMOVER ESTILOS
            sanitized = STYLE_PATTERN.matcher(sanitized).replaceAll("");

            // 3️⃣ REMOVER TODAS LAS ETIQUETAS HTML
            sanitized = ALL_HTML_PATTERN.matcher(sanitized).replaceAll("");

            // 4️⃣ REMOVER JAVASCRIPT/VBSCRIPT URLs
            sanitized = JAVASCRIPT_PATTERN.matcher(sanitized).replaceAll("removed:");
            sanitized = VBSCRIPT_PATTERN.matcher(sanitized).replaceAll("removed:");

            // 5️⃣ REMOVER DATA URLs sospechosas
            sanitized = DATA_URL_PATTERN.matcher(sanitized).replaceAll("data-removed:");

            // 6️⃣ REMOVER EVENTOS JAVASCRIPT
            sanitized = DANGEROUS_EVENTS_PATTERN.matcher(sanitized).replaceAll("removed=");

            return sanitized.trim();

        } catch (Exception e) {
            logger.error("❌ Error sanitizando HTML: {}", e.getMessage());
            return ""; // En caso de error, devolver string vacío por seguridad
        }
    }

    /**
     * 🎨 Sanitizar texto rico manteniendo formato básico seguro
     * Uso: biografías, descripciones (cuando permitas HTML básico)
     */
    public static String sanitizeRichText(String input) {
        if (input == null) {
            return null;
        }

        if (input.trim().isEmpty()) {
            return input;
        }

        try {
            // 🔍 LOG PARA DETECTAR INTENTOS DE INYECCIÓN
            if (containsSuspiciousContent(input)) {
                logger.warn("🚨 Contenido rico sospechoso detectado: {}",
                        input.length() > 50 ? input.substring(0, 50) + "..." : input);
            }

            String sanitized = input;

            // 1️⃣ REMOVER CONTENIDO PELIGROSO PRIMERO
            sanitized = SCRIPT_PATTERN.matcher(sanitized).replaceAll("");
            sanitized = STYLE_PATTERN.matcher(sanitized).replaceAll("");
            sanitized = JAVASCRIPT_PATTERN.matcher(sanitized).replaceAll("removed:");
            sanitized = VBSCRIPT_PATTERN.matcher(sanitized).replaceAll("removed:");
            sanitized = DANGEROUS_EVENTS_PATTERN.matcher(sanitized).replaceAll("removed=");

            // 2️⃣ PERMITIR SOLO ETIQUETAS BÁSICAS SEGURAS
            sanitized = sanitized.replaceAll("(?i)<(?!/?(?:p|br|b|i|u|strong|em)\\b)[^>]*>", "");

            return sanitized.trim();

        } catch (Exception e) {
            logger.error("❌ Error sanitizando texto rico: {}", e.getMessage());
            return stripAllTags(input); // Fallback a sanitización completa
        }
    }

    /**
     * 🔒 Codificar caracteres HTML para prevenir XSS
     * Uso: cuando necesites mostrar contenido que puede contener < > &
     */
    public static String htmlEncode(String input) {
        if (input == null) {
            return null;
        }

        if (input.trim().isEmpty()) {
            return input;
        }

        String encoded = input;

        // Codificar caracteres peligrosos
        for (int i = 0; i < DANGEROUS_CHARS.length; i++) {
            encoded = DANGEROUS_CHARS[i].matcher(encoded).replaceAll(SAFE_REPLACEMENTS[i]);
        }

        return encoded;
    }

    /**
     * 🧼 Sanitización específica para campos de usuario
     * Uso: usernames, nombres, campos que no deberían tener HTML
     */
    public static String sanitizeUserInput(String input) {
        if (input == null) {
            return null;
        }

        // 1️⃣ STRIP HTML TAGS
        String sanitized = stripAllTags(input);

        // 2️⃣ LIMPIAR ESPACIOS EXCESIVOS
        sanitized = sanitized.replaceAll("\\s+", " ");

        // 3️⃣ REMOVER CARACTERES DE CONTROL
        sanitized = sanitized.replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "");

        return sanitized.trim();
    }

    /**
     * 🔍 Detectar contenido sospechoso para logging
     */
    private static boolean containsSuspiciousContent(String input) {
        if (input == null) {
            return false;
        }

        String lowerInput = input.toLowerCase();

        return lowerInput.contains("<script") ||
                lowerInput.contains("javascript:") ||
                lowerInput.contains("vbscript:") ||
                lowerInput.contains("onload=") ||
                lowerInput.contains("onerror=") ||
                lowerInput.contains("onclick=") ||
                lowerInput.contains("expression(") ||
                lowerInput.contains("<iframe") ||
                lowerInput.contains("<object") ||
                lowerInput.contains("<embed");
    }

    /**
     * 🛡️ Validar que un string no contenga HTML malicioso
     * Uso: validaciones antes de guardar en base de datos
     */
    public static boolean isSafeContent(String input) {
        if (input == null) {
            return true;
        }

        return !containsSuspiciousContent(input);
    }

    /**
     * 📊 Obtener estadísticas de sanitización (para debugging)
     */
    public static SanitizationResult sanitizeWithStats(String input) {
        if (input == null) {
            return new SanitizationResult(null, false, 0);
        }

        String original = input;
        boolean wasSuspicious = containsSuspiciousContent(input);
        String sanitized = stripAllTags(input);
        int removedChars = original.length() - sanitized.length();

        return new SanitizationResult(sanitized, wasSuspicious, removedChars);
    }

    /**
     * 📊 Resultado de sanitización con estadísticas
     */
    public static class SanitizationResult {
        private final String sanitizedContent;
        private final boolean wasSuspicious;
        private final int removedCharacters;

        public SanitizationResult(String sanitizedContent, boolean wasSuspicious, int removedCharacters) {
            this.sanitizedContent = sanitizedContent;
            this.wasSuspicious = wasSuspicious;
            this.removedCharacters = removedCharacters;
        }

        public String getSanitizedContent() {
            return sanitizedContent;
        }

        public boolean wasSuspicious() {
            return wasSuspicious;
        }

        public int getRemovedCharacters() {
            return removedCharacters;
        }
    }
}