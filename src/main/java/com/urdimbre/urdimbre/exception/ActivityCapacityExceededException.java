package com.urdimbre.urdimbre.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class ActivityCapacityExceededException extends RuntimeException {

    public ActivityCapacityExceededException(String message) {
        super(message);
    }

    public ActivityCapacityExceededException(String message, Throwable cause) {
        super(message, cause);
    }
}