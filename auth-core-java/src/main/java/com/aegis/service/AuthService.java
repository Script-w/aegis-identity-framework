package com.aegis.service;

import com.aegis.model.User;
import com.aegis.repository.UserRepository;
import com.aegis.security.PasswordHasher;
import com.aegis.service.MfaClient.MfaSetupResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final MfaClient mfaClient;

    public AuthService(UserRepository userRepository, PasswordHasher passwordHasher, MfaClient mfaClient) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.mfaClient = mfaClient;
    }

    public MfaSetupResult initiateMfaSetup(String username) {
        return userRepository.findByUsername(username)
            .map(user -> {
                // Pre-Flight: In production, generate a unique secret per user
                String secret = "JBSWY3DPEHPK3PXP"; 
                
                // Call the Python Brain for the QR Code
                return mfaClient.getQrCode(username, secret)
                        .orElse(MfaSetupResult.failure("No response from Security Brain"));
            })
            .orElseThrow(() -> new RuntimeException("User not found"));
    }
    
    public void registerUser(String username, String password) {
        if (userRepository.findByUsername(username).isPresent()) {
            log.warn("Registration rejected for existing username");
            throw new RuntimeException("Username already taken!");
        }

        String securedHash = passwordHasher.hash(password);

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPasswordHash(securedHash); 

        userRepository.save(newUser);
        log.info("User registration succeeded");
    }

    public boolean verifyLogin(String username, String password) {
        boolean verified = userRepository.findByUsername(username)
            .map(user -> {
                char[] passwordChars = password.toCharArray();
                return passwordHasher.verify(user.getPasswordHash(), passwordChars);
            })
            .orElse(false);
        log.info("Login attempt completed with success={}", verified);
        return verified;
    }
}
