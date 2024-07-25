package com.example.spring_security_custom.dto;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public record LoginResponseDTO(String accessToken, String refreshToken,
                               Collection<? extends GrantedAuthority> roles,
                               String message) {
}
