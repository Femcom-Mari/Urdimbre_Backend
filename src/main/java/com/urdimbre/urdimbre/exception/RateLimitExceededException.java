package com.urdimbre.urdimbre.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import lombok.Getter;

@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
@Getter
public class RateLimitExceededException extends RuntimeException {

    private final long retryAfterSeconds;
    private final String rateLimitType;

    public RateLimitExceededException(String message, long retryAfterSeconds, String rateLimitType) {
        super(message);
        this.retryAfterSeconds = retryAfterSeconds;
        this.rateLimitType = rateLimitType;
    }

    public RateLimitExceededException(String message, long retryAfterSeconds) {
        this(message, retryAfterSeconds, "general");
    }

    public static RateLimitExceededException forLoginByIp(long retryAfterSeconds) {
        return new RateLimitExceededException(
                "Demasiados intentos de login desde esta IP. Intenta nuevamente en " + retryAfterSeconds + " segundos.",
                retryAfterSeconds,
                "login_ip");
    }

    public static RateLimitExceededException forLoginByUser(String username, long retryAfterSeconds) {
        return new RateLimitExceededException(
                "Demasiados intentos de login para el usuario '" + username + "'. Intenta nuevamente en "
                        + retryAfterSeconds + " segundos.",
                retryAfterSeconds,
                "login_user");
    }

    public static RateLimitExceededException forRegisterByIp(long retryAfterSeconds) {
        return new RateLimitExceededException(
                "Demasiados intentos de registro desde esta IP. Intenta nuevamente en " + retryAfterSeconds
                        + " segundos.",
                retryAfterSeconds,
                "register_ip");
    }

    public static RateLimitExceededException forGeneral(String message, long retryAfterSeconds) {
        return new RateLimitExceededException(message, retryAfterSeconds, "general");
    }

    public static RateLimitExceededException forApiCall(String endpoint, long retryAfterSeconds) {
        return new RateLimitExceededException(
                "Rate limit exceeded para endpoint: " + endpoint + ". Intenta nuevamente en " + retryAfterSeconds
                        + " segundos.",
                retryAfterSeconds,
                "api_call");
    }

    public static RateLimitExceededException forPasswordReset(long retryAfterSeconds) {
        return new RateLimitExceededException(
                "Demasiados intentos de reset de contraseña. Intenta nuevamente en " + retryAfterSeconds + " segundos.",
                retryAfterSeconds,
                "password_reset");
    }

    public boolean isLoginRelated() {
        return "login_ip".equals(rateLimitType) || "login_user".equals(rateLimitType);
    }

    public boolean isRegistrationRelated() {
        return "register_ip".equals(rateLimitType);
    }

    public boolean isIpBased() {
        return rateLimitType != null && rateLimitType.contains("_ip");
    }

    public boolean isUserBased() {
        return rateLimitType != null && rateLimitType.contains("_user");
    }

    @Override
    public String toString() {
        return String.format("RateLimitExceededException{type='%s', retryAfter=%d, message='%s'}",
                rateLimitType, retryAfterSeconds, getMessage());
    }
}