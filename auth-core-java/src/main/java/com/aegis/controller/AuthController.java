package com.aegis.controller;

import com.aegis.dto.RegistrationRequest;
import com.aegis.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor // Lombok generates the constructor for AuthService
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegistrationRequest request) {
        authService.registerUser(request.getUsername(), request.getPassword());
        return ResponseEntity.ok("User registered successfully. Proceed to MFA enrollment.");
    }
}
