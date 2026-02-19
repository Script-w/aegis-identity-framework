package com.aegis.service;

import com.aegis.model.User;
import com.aegis.repository.UserRepository;
import com.aegis.security.PasswordHasher;
import com.aegis.service.MfaClient.MfaSetupResult;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor // This handles the injection for all 'final' fields automatically
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final MfaClient mfaClient;

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
            throw new RuntimeException("Username already taken!");
        }

        String securedHash = passwordHasher.hash(password);

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPasswordHash(securedHash); 

        userRepository.save(newUser);
    }

    public boolean verifyLogin(String username, String password) {
        return userRepository.findByUsername(username)
            .map(user -> {
                char[] passwordChars = password.toCharArray();
                return passwordHasher.verify(user.getPasswordHash(), passwordChars);
            })
            .orElse(false);
    }
}
