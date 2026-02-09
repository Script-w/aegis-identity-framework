package com.aegis.service;

import com.aegis.model.User;
import com.aegis.repository.UserRepository;
import com.aegis.security.PasswordHasher;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;

    public void registerUser(String username, String password) {
        // 1. Pre-Flight Check: Check for existing user
        if (userRepository.findByUsername(username).isPresent()) {
            throw new RuntimeException("Username already taken!");
        }

        // 2. Hash the password with Argon2id
        String securedHash = passwordHasher.hash(password);

        // 3. Save the secured user to Supabase
        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPasswordHash(securedHash); 

        userRepository.save(newUser);
    }

    public boolean verifyLogin(String username, String password) {
        User user = userRepository.findByUsername(username);
        if (user != null) {
            // Convert the String to char[] right at the gate
            char[] passwordChars = password.toCharArray();
            return passwordHasher.verify(user.getPasswordHash(), passwordChars);
        }
        return false;
    }
    
}
