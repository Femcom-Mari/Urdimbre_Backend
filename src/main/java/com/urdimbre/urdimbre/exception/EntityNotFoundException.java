package com.urdimbre.urdimbre.exception;

public class EntityNotFoundException extends RuntimeException {
    public EntityNotFoundException (String message) {
        super(message);
    }
}
