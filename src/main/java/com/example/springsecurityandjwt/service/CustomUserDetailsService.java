package com.example.springsecurityandjwt.service;

import com.example.springsecurityandjwt.dto.CustomUserDetails;
import com.example.springsecurityandjwt.entity.UserEntity;
import com.example.springsecurityandjwt.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {

        UserEntity userEntity = userRepository.findByUserId(userId);
        if (userEntity != null) {
            return new CustomUserDetails(userEntity);
        } else {
            throw new UsernameNotFoundException("User not found with username: " + userId);
        }
    }
}
