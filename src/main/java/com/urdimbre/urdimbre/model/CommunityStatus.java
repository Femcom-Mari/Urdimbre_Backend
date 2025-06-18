package com.urdimbre.urdimbre.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum CommunityStatus {

    ASSOCIATED("Associated"),
    NOT_ASSOCIATED("Not associated");

    private final String displayValue;

    CommunityStatus(String displayValue) {
        this.displayValue = displayValue;
    }

    @JsonValue
    public String getDisplayValue() {
        return displayValue;
    }

    @JsonCreator
    public static CommunityStatus fromDisplayValue(String value) {
        for (CommunityStatus status : values()) {
            if (status.displayValue.equalsIgnoreCase(value)) {
                return status;
            }
        }
        throw new IllegalArgumentException("Invalid community status: " + value +
                ". Valid values are: 'Associated', 'Not associated'");
    }

    @Override
    public String toString() {
        return displayValue;
    }
}

