package com.aegis.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class RegistrationRequest {
    @NotBlank(message = "username is required")
    @Size(min = 3, max = 50, message = "username must be between 3 and 50 characters")
    @Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9._-]*$",
            message = "username may contain letters, numbers, dots, underscores, and hyphens")
    private String username;

    @NotBlank(message = "password is required")
    @Size(min = 8, max = 128, message = "password must be between 8 and 128 characters")
    private String password;

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
}
