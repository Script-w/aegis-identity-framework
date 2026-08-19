package com.aegis.controller;

import com.aegis.dto.RegistrationRequest;
import com.aegis.dto.LoginRequest;
import com.aegis.service.AuthService;
import com.aegis.security.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;
    private final String cookieName;
    private final boolean cookieSecure;

    public AuthController(AuthService authService, JwtService jwtService,
                          @Value("${auth.cookie.name:AEGIS_TOKEN}") String cookieName,
                          @Value("${auth.cookie.secure:false}") boolean cookieSecure) {
        this.authService = authService;
        this.jwtService = jwtService;
        this.cookieName = cookieName;
        this.cookieSecure = cookieSecure;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegistrationRequest request) {
        authService.registerUser(request.getUsername(), request.getPassword());
        return ResponseEntity.ok("User registered successfully. Proceed to MFA enrollment.");
    }

    @PostMapping("/login")
    public ResponseEntity<Void> login(@RequestBody LoginRequest request) {
        if (!authService.verifyLogin(request.getUsername(), request.getPassword())) {
            return ResponseEntity.status(401).build();
        }

        ResponseCookie cookie = ResponseCookie.from(cookieName, jwtService.generateToken(request.getUsername()))
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/")
                .maxAge(Duration.ofMillis(jwtService.getExpirationMs()))
                .build();
        return ResponseEntity.ok().header("Set-Cookie", cookie.toString()).build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        ResponseCookie cookie = ResponseCookie.from(cookieName, "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Strict")
                .path("/")
                .maxAge(Duration.ZERO)
                .build();
        return ResponseEntity.ok().header("Set-Cookie", cookie.toString()).build();
    }
}
