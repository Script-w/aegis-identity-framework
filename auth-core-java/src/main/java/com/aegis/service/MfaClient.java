package com.aegis.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.Map;
import java.util.HashMap;

@Service
public class MfaClient {

    private final RestTemplate restTemplate;
    
    // This value is injected from your .env file via application.properties
    @Value("${aegis.security.brain-url}")
    private String securityBrainUrl;

    public MfaClient(RestTemplate restTemplate, @Value("${aegis.security.brain-url}") String securityBrainUrl) {
        this.restTemplate = restTemplate;
        this.securityBrainUrl = securityBrainUrl;
    }

    public String getQrCode(String username, String secret) {
        String endpoint = securityBrainUrl + "/mfa/setup";

        // Preparing the payload for the Python Pydantic model
        Map<String, String> request = new HashMap<>();
        request.put("username", username);
        request.put("secret", secret);

        try {
            // Calling the Python FastAPI service
            Map<String, Object> response = restTemplate.postForObject(endpoint, request, Map.class);
            
            // Extracting the base64 string from the "data" nested object
            if (response != null && response.containsKey("data")) {
                Map<String, String> data = (Map<String, String>) response.get("data");
                return data.get("qr_code");
            }
        } catch (Exception e) {
            // In a Legacy Scaling framework, we log this and provide a fallback
            System.err.println("Failed to connect to Security Brain: " + e.getMessage());
        }
        return null;
    }
}