package com.example.springsecurityandjwt.repository;

import com.example.springsecurityandjwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Boolean existsByUserId(String userId);

    UserEntity findByUserId(String userId);
}
