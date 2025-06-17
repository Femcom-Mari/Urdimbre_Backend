package com.urdimbre.urdimbre.exception;

import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ErrorDetails {

    private final Date timestamp;
    private final String message;
    private final String details;
}