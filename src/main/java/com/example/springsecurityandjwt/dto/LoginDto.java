package com.example.springsecurityandjwt.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Getter
@Setter
public class LoginDto {
    private String userId;
    private String password;
}
