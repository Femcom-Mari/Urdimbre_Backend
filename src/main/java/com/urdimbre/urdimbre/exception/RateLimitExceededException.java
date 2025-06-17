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
}
