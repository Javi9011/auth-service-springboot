package com.nelson.security.authservice.Controller;

import com.nelson.security.authservice.model.User;
import com.nelson.security.authservice.model.Enums.Role;
import com.nelson.security.authservice.repository.UserRepository;
import jakarta.security.auth.message.AuthException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // ✅ Registrar nuevo usuario con rol USER
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("El nombre de usuario ya existe");
        }

        user.setRole(Role.USER);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return ResponseEntity.ok("Usuario registrado correctamente");
    }

    // ✅ Listar todos los usuarios (solo ADMIN)
    @GetMapping("/all")
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> getUsers() {
        return userRepository.findAll();
    }

    // ✅ Obtener perfil del usuario autenticado
    @GetMapping("/profile")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<User> getProfile(Authentication authentication) {
        String username = authentication.getName();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));
        return ResponseEntity.ok(user);
    }

    // ✅ Promover usuario a ADMIN (solo ADMIN puede hacerlo)
    @PutMapping("/promote/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> promoteToAdmin(@PathVariable String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        user.setRole(Role.ADMIN);
        userRepository.save(user);

        return ResponseEntity.ok("Usuario promovido a ADMIN");
    }

    // ✅ Eliminar usuario por ID (solo ADMIN)
    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> deleteUser(@PathVariable Long id, Authentication authentication) {
        if (!userRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }

        // Previene que un ADMIN se elimine a sí mismo
        User userToDelete = userRepository.findById(id).orElseThrow();
        if (userToDelete.getUsername().equals(authentication.getName())) {
            return ResponseEntity.badRequest().body("No puedes eliminar tu propio usuario");
        }

        userRepository.deleteById(id);
        return ResponseEntity.ok("Usuario eliminado con éxito");
    }
}
