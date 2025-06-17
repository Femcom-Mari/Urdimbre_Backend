// src/main/java/com/urdimbre/urdimbre/exception/InviteCodeException.java
package com.urdimbre.urdimbre.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * 🎟️ Excepción específica para problemas con códigos de invitación
 * Usada en lugar de RuntimeException genérica para mejor manejo de errores
 */
@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class InviteCodeException extends RuntimeException {

    public InviteCodeException(String message) {
        super(message);
    }

    public InviteCodeException(String message, Throwable cause) {
        super(message, cause);
    }

    // ✅ MÉTODOS ESTÁTICOS PARA CASOS ESPECÍFICOS
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