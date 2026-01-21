package com.example.JWT.service;


import com.example.JWT.model.User;
import com.example.JWT.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final UserRepository repository;
    private final PasswordEncoder encoder;

    public UserService(UserRepository repository, PasswordEncoder encoder) {
        this.repository = repository;
        this.encoder = encoder;
    }

    public User createUser(User user) {

        if (repository.existsByUsername(user.getUsername())) {
            throw new RuntimeException("Usuário já existe");
        }

        user.setPassword(encoder.encode(user.getPassword()));

        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            user.setRoles(List.of("ROLE_USER"));
        }

        return repository.save(user);
    }
}

