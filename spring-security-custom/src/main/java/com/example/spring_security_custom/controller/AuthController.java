package com.example.spring_security_custom.controller;


import com.example.spring_security_custom.dto.LoginDTO;
import com.example.spring_security_custom.dto.LoginResponseDTO;
import com.example.spring_security_custom.dto.RegisterDTO;
import com.example.spring_security_custom.dto.UserDTO;
import com.example.spring_security_custom.service.AuthService;
import jakarta.validation.Valid;
import lombok.Getter;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService userService;

    public AuthController(AuthService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<UserDTO> register(@RequestBody @Valid RegisterDTO registerDTO) {
        UserDTO createdUser = userService.register(registerDTO);
        return ResponseEntity.ok(createdUser);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody @Valid LoginDTO loginRequest) {

        return ResponseEntity.ok(userService.login(loginRequest));
    }

    @GetMapping("/user")
    public ResponseEntity<String> helloUser(){
        return ResponseEntity.ok("Hello users World");
    }
}
