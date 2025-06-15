package com.nelson.security.authservice.Controller;

import com.nelson.security.authservice.model.User;
import com.nelson.security.authservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class UserController {

    @Autowired
    private UserRepository userRepository;

    // Endpoint para listar todos los usuarios
    @GetMapping("/users")
    public List<User> getUsers() {
        return userRepository.findAll();
    }

    // Endpoint para registrar un nuevo usuario
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user) {
        System.out.println("Usuario recibido: " + user.getUsername());
        userRepository.save(user);
        return ResponseEntity.ok("Usuario registrado correctamente");
    }
}
