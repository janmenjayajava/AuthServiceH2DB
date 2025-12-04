package com.app.auth.controller;


import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.app.auth.dto.LoginRequest;
import com.app.auth.dto.RegisterRequest;
import com.app.auth.entity.User;
import com.app.auth.service.AuthService;

import java.security.Principal;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest req) {
        authService.register(req);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest req) {
        String token = authService.login(req);
        return ResponseEntity.ok(new TokenResponse(token));
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponse> me(Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        User u = authService.getCurrentUser(principal.getName());
        if (u == null) return ResponseEntity.notFound().build();
        UserResponse resp = new UserResponse(u.getId(), u.getEmail(), u.getRoles());
        return ResponseEntity.ok(resp);
    }

    // small response DTOs as inner static classes to avoid extra files for now
    public static record TokenResponse(String token) {}
    public static record UserResponse(Long id, String email, Set<String> roles) {}
}
