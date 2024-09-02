package com.example.springsecurityandjwt.controller;

import com.example.springsecurityandjwt.dto.JoinDto;
import com.example.springsecurityandjwt.service.JoinService;
import jakarta.persistence.Entity;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public ResponseEntity<String> join(@RequestBody JoinDto joinDto) {
        if (joinService.joinProcess(joinDto.getUserId(), joinDto.getPassword())) {
            return ResponseEntity.ok("Join Success");
        } else {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }
    }
}
