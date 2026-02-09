package com.aegis.service;

import com.aegis.model.User;
import com.aegis.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    public void registerUser(String username, String password) {
        // Pre-Flight Check: Does the user already exist?
        if (userRepository.findByUsername(username).isPresent()) {
            throw new RuntimeException("Username already taken!");
        }

        User newUser = new User();
        newUser.setUsername(username);
        
        // TODO: In the next step, we'll wrap this in Argon2id hashing
        newUser.setPasswordHash(password); 

        userRepository.save(newUser);
    }
}
