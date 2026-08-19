package com.aegis.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class LoginRequest {
    @NotBlank(message = "username is required")
    @Size(min = 3, max = 50, message = "username must be between 3 and 50 characters")
    @Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9._-]*$",
            message = "username may contain letters, numbers, dots, underscores, and hyphens")
    private String username;

    @NotBlank(message = "password is required")
    @Size(max = 128, message = "password must not exceed 128 characters")
    private String password;

    @Pattern(regexp = "\\d{6}", message = "mfaCode must contain exactly 6 digits")
    private String mfaCode;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getMfaCode() {
        return mfaCode;
    }

    public void setMfaCode(String mfaCode) {
        this.mfaCode = mfaCode;
    }
}
