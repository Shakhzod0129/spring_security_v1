package com.example.spring_security_custom.security.user;

import com.example.spring_security_custom.entity.User;
import com.example.spring_security_custom.exp.UserNotFoundException;
import com.example.spring_security_custom.repo.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository profileRepository;

    public CustomUserDetailsService(UserRepository profileRepository) {
        this.profileRepository = profileRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> optional = profileRepository.findByUsername(username);
        if (optional.isEmpty()) {
            throw new UserNotFoundException("User not found :"+username);
        }
        return new UserDetailsImpl(optional.get()) {
        };
    }
}