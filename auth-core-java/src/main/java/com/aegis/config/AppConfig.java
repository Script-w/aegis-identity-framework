package com.aegis.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AppConfig {

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
        // In Legacy Scaling, you'd add timeouts here so a slow 'Brain' 
        // doesn't hang your 'Heart'.
    }
}
    