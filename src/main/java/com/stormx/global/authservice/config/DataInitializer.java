package com.stormx.global.authservice.config;

import com.stormx.global.authservice.entity.Role;
import com.stormx.global.authservice.repository.RoleRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor

public class DataInitializer {
    private final RoleRepository roleRepository;

    @PostConstruct
    public void init() {
        // Initialize roles if they do not exist
        if (roleRepository.findByName("ROLE_USER").isEmpty()) {
            roleRepository.save(new Role(null, "ROLE_USER"));
        }

        if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
            roleRepository.save(new Role(null, "ROLE_ADMIN"));
        }

        if (roleRepository.findByName("ROLE_MODERATOR").isEmpty()) {
            roleRepository.save(new Role(null, "ROLE_MODERATOR"));
        }
    }
}
