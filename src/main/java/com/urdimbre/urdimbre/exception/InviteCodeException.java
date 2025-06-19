package com.urdimbre.urdimbre.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class InviteCodeException extends RuntimeException {

    public InviteCodeException(String message) {
        super(message);
    }

    public InviteCodeException(String message, Throwable cause) {
        super(message, cause);
    }

    public static InviteCodeException codeGenerationFailed(String reason) {
        return new InviteCodeException("Error generando código de invitación: " + reason);
    }

    public static InviteCodeException invalidCodeFormat(String code) {
        return new InviteCodeException("Formato de código inválido: " + code);
    }

    public static InviteCodeException codeAlreadyExists(String code) {
        return new InviteCodeException("El código ya existe: " + code);
    }
}