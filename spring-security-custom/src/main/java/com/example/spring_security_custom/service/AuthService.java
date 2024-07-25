package com.example.spring_security_custom.service;

import com.example.spring_security_custom.dto.LoginDTO;
import com.example.spring_security_custom.dto.LoginResponseDTO;
import com.example.spring_security_custom.dto.RegisterDTO;
import com.example.spring_security_custom.dto.UserDTO;
import com.example.spring_security_custom.entity.User;
import com.example.spring_security_custom.enums.Role;
import com.example.spring_security_custom.exp.AlreadyExistsException;
import com.example.spring_security_custom.exp.InvalidPasswordException;
import com.example.spring_security_custom.exp.UserNotFoundException;
import com.example.spring_security_custom.mapper.UserMapper;
import com.example.spring_security_custom.repo.UserRepository;
import com.example.spring_security_custom.security.jwt.JWTService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Slf4j
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;

    public AuthService(UserRepository userRepository, UserMapper userMapper, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JWTService jwtService) {
        this.userRepository = userRepository;
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    public UserDTO register(RegisterDTO registerDTO) {
        Optional<User> optional = userRepository.findByUsername(registerDTO.getUsername());

        if (optional.isPresent()) {
            log.warn("Username already exists");
            throw new AlreadyExistsException("Username already exists");
        }

        User user = new User();
        user.setUsername(registerDTO.getUsername());
        user.setPassword(passwordEncoder.encode(registerDTO.getPassword()));
        Set<Role> roles = new HashSet<>();
        roles.add(Role.ROLE_USER); // Add default role
        user.setRoles(roles);

        // Save the new User to the database
        userRepository.save(user);

        return userMapper.toDTO(user);
    }


    public LoginResponseDTO login(LoginDTO loginRequest) {

        Optional<User> optional = userRepository.findByUsername(loginRequest.username());

        if (optional.isEmpty()) {
            log.warn("Username not found :{}", loginRequest.username());
            throw new UserNotFoundException("Username not found : " + loginRequest.username());
        }

        try {
            Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    loginRequest.username(),
                    loginRequest.password()
            ));

            UserDetails userDetails = (UserDetails) authenticate.getPrincipal();

            String accessToken = jwtService.generateAccessToken(userDetails.getUsername());
            String refreshToken = jwtService.generateRefreshToken(userDetails.getUsername());

            return new LoginResponseDTO(accessToken, refreshToken, userDetails.getAuthorities(), "Login successfully");

        } catch (BadCredentialsException ex) {
            throw new InvalidPasswordException("Invalid username or password");
        } catch (Exception ex) {
            log.error("An error occurred during login for user: {}", loginRequest.username(), ex);
            throw new RuntimeException("Login failed, please try again later");
        }
    }

}
