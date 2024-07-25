package com.example.spring_security_custom.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Request body for Login")
public record LoginDTO(@NotBlank(message = "username must be not blank.")
                       @Schema(description = "username", example = "john")
                       String username,
                       @NotBlank(message = "password must be not blank.")
                       @Schema(description = "password", example = "12345")
                       String password) {
}