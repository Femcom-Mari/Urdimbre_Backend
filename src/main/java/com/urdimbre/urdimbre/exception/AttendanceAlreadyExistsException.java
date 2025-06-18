package com.urdimbre.urdimbre.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class AttendanceAlreadyExistsException extends RuntimeException {

    public AttendanceAlreadyExistsException(String message) {
        super(message);
    }

    public AttendanceAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }
}