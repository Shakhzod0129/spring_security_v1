package com.example.spring_security_custom.mapper;

import com.example.spring_security_custom.dto.UserDTO;
import com.example.spring_security_custom.entity.User;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

    public UserDTO toDTO(User user) {
        if (user == null) {
            return null;
        }

        UserDTO userDTO = new UserDTO();
        userDTO.setId(user.getId());
        userDTO.setUsername(user.getUsername());
        userDTO.setRoles(user.getRoles());// Custom field mapping
        // Set other fields as needed

        return userDTO;
    }

    public User toEntity(UserDTO userDTO) {
        if (userDTO == null) {
            return null;
        }

        User user = new User();
        user.setId(userDTO.getId());
        user.setUsername(userDTO.getUsername());
        user.setRoles(userDTO.getRoles());// Custom field mapping
        // Set other fields as needed

        return user;
    }
}
