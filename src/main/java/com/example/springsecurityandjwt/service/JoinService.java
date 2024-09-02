package com.example.springsecurityandjwt.service;

import com.example.springsecurityandjwt.entity.UserEntity;
import com.example.springsecurityandjwt.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@AllArgsConstructor
public class JoinService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Transactional
    public boolean joinProcess(String userId, String password) {
        if (userRepository.existsByUserId(userId)) {
            return false;
        } else {
            UserEntity joinUserData = new UserEntity();
            joinUserData.setUserId(userId);
            joinUserData.setPassword(bCryptPasswordEncoder.encode(password));
            joinUserData.setRole("ROLE_USER");
            userRepository.save(joinUserData);
            return true;
        }
    }
}
