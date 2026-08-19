package com.aegis.controller;

import com.aegis.dto.RegistrationRequest;
import com.aegis.dto.LoginRequest;
import com.aegis.dto.MfaCodeRequest;
import com.aegis.service.AuthService;
import com.aegis.service.MfaClient;
import com.aegis.security.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;
import jakarta.validation.Valid;

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
    public ResponseEntity<String> register(@Valid @RequestBody RegistrationRequest request) {
        authService.registerUser(request.getUsername(), request.getPassword());
        return ResponseEntity.ok("User registered successfully. Proceed to MFA enrollment.");
    }

    @PostMapping("/login")
    public ResponseEntity<Void> login(@Valid @RequestBody LoginRequest request) {
        if (!authService.verifyLogin(request.getUsername(), request.getPassword(), request.getMfaCode())) {
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

    @GetMapping("/mfa/setup")
    public ResponseEntity<MfaClient.MfaSetupResult> setupMfa(Authentication authentication) {
        return ResponseEntity.ok(authService.initiateMfaSetup(authentication.getName()));
    }

    @PostMapping("/mfa/confirm")
    public ResponseEntity<Void> confirmMfa(Authentication authentication, @Valid @RequestBody MfaCodeRequest request) {
        if (!authService.confirmMfaSetup(authentication.getName(), request.getCode())) {
            return ResponseEntity.status(400).build();
        }
        return ResponseEntity.ok().build();
    }
}
