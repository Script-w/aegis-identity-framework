package com.aegis.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class MfaCodeRequest {
    @NotBlank(message = "code is required")
    @Pattern(regexp = "\\d{6}", message = "code must contain exactly 6 digits")
    private String code;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
