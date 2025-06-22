package com.urdimbre.urdimbre.util;

import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HtmlSanitizer {

    private static final Logger logger = LoggerFactory.getLogger(HtmlSanitizer.class);

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

    private static final Pattern DANGEROUS_EVENTS_PATTERN = Pattern.compile(
            "(?i)(on\\w+\\s*=|expression\\s*\\()", Pattern.CASE_INSENSITIVE);

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
    }

    public static String stripAllTags(String input) {
        if (input == null) {
            return null;
        }

        if (input.trim().isEmpty()) {
            return input;
        }

        try {
            if (containsSuspiciousContent(input)) {
                logger.warn("Contenido sospechoso detectado y sanitizado: {}",
                        input.length() > 50 ? input.substring(0, 50) + "..." : input);
            }

            String sanitized = input;

            sanitized = SCRIPT_PATTERN.matcher(sanitized).replaceAll("");
            sanitized = STYLE_PATTERN.matcher(sanitized).replaceAll("");
            sanitized = ALL_HTML_PATTERN.matcher(sanitized).replaceAll("");
            sanitized = JAVASCRIPT_PATTERN.matcher(sanitized).replaceAll("removed:");
            sanitized = VBSCRIPT_PATTERN.matcher(sanitized).replaceAll("removed:");
            sanitized = DATA_URL_PATTERN.matcher(sanitized).replaceAll("data-removed:");
            sanitized = DANGEROUS_EVENTS_PATTERN.matcher(sanitized).replaceAll("removed=");

            return sanitized.trim();

        } catch (Exception e) {
            logger.error("Error sanitizando HTML: {}", e.getMessage());
            return "";
        }
    }

    public static String sanitizeRichText(String input) {
        if (input == null) {
            return null;
        }

        if (input.trim().isEmpty()) {
            return input;
        }

        try {
            if (containsSuspiciousContent(input)) {
                logger.warn("Contenido rico sospechoso detectado: {}",
                        input.length() > 50 ? input.substring(0, 50) + "..." : input);
            }

            String sanitized = input;

            sanitized = SCRIPT_PATTERN.matcher(sanitized).replaceAll("");
            sanitized = STYLE_PATTERN.matcher(sanitized).replaceAll("");
            sanitized = JAVASCRIPT_PATTERN.matcher(sanitized).replaceAll("removed:");
            sanitized = VBSCRIPT_PATTERN.matcher(sanitized).replaceAll("removed:");
            sanitized = DANGEROUS_EVENTS_PATTERN.matcher(sanitized).replaceAll("removed=");

            sanitized = sanitized.replaceAll("(?i)<(?!/?(?:p|br|b|i|u|strong|em)\\b)[^>]*>", "");

            return sanitized.trim();

        } catch (Exception e) {
            logger.error("Error sanitizando texto rico: {}", e.getMessage());
            return stripAllTags(input);
        }
    }

    public static String htmlEncode(String input) {
        if (input == null) {
            return null;
        }

        if (input.trim().isEmpty()) {
            return input;
        }

        String encoded = input;

        for (int i = 0; i < DANGEROUS_CHARS.length; i++) {
            encoded = DANGEROUS_CHARS[i].matcher(encoded).replaceAll(SAFE_REPLACEMENTS[i]);
        }

        return encoded;
    }

    public static String sanitizeUserInput(String input) {
        if (input == null) {
            return null;
        }

        String sanitized = stripAllTags(input);
        sanitized = sanitized.replaceAll("\\s+", " ");
        sanitized = sanitized.replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "");

        return sanitized.trim();
    }

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

    public static boolean isSafeContent(String input) {
        if (input == null) {
            return true;
        }

        return !containsSuspiciousContent(input);
    }

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