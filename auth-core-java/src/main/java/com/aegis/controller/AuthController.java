package com.aegis.controller;

import com.aegis.dto.RegistrationRequest;
import com.aegis.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegistrationRequest request) {
        authService.registerUser(request.getUsername(), request.getPassword());
        return ResponseEntity.ok("User registered successfully. Proceed to MFA enrollment.");
    }
}
