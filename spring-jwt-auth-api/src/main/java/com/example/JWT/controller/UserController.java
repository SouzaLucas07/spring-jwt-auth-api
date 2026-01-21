package com.example.JWT.controller;

import com.example.JWT.model.User; // Import correto do seu modelo
import com.example.JWT.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService service;

    @PostMapping
    public ResponseEntity<User> postUser(@RequestBody User user){
        User savedUser = service.createUser(user); // Chama o serviço correto
        return ResponseEntity.status(HttpStatus.CREATED).body(savedUser);
    }
}