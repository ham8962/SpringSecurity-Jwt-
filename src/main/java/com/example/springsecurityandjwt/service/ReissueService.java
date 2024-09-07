package com.example.springsecurityandjwt.service;

import com.example.springsecurityandjwt.entity.RefreshEntity;
import com.example.springsecurityandjwt.jwt.JWTUtil;
import com.example.springsecurityandjwt.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@AllArgsConstructor
public class ReissueService {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh-token)")) {
                refreshToken = cookie.getValue();
            }
        }
        if (refreshToken == null) {
            return ResponseEntity.badRequest().build();
        }
        try {
            jwtUtil.isExpired(refreshToken);
        } catch (ExpiredJwtException e) {
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }
        String category = jwtUtil.getCategory(refreshToken);
        if (!category.equals("refresh-token")) {
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }
        // refresh 토큰이 DB에 있는지 확인
        Boolean exists = refreshRepository.existsByRefreshToken(refreshToken);
        if (!exists) {
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }
        String userId = jwtUtil.getUserId(refreshToken);
        String role = jwtUtil.getRole(refreshToken);
        String newAccessToken = jwtUtil.createJwt("access", userId, role, 600000L);
        // refresh token rotating
        String newRefreshToken = jwtUtil.createJwt("refresh", userId, role, 86400000L);
        refreshRepository.deleteByRefreshToken(refreshToken);
        // refresh token 새로 저장
        addRefreshToken(userId, newRefreshToken, 86400000L);
        response.setHeader("access-token", newAccessToken);
        response.addCookie(createCookie("refresh-token", newRefreshToken));
        return ResponseEntity.ok().build();
    }

    private Cookie createCookie(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(86400);
        return cookie;
    }

    private void addRefreshToken(String userId, String refreshToken, Long expiration) {
        Date date = new Date(System.currentTimeMillis() + expiration);
        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUserId(userId);
        refreshEntity.setRefreshToken(refreshToken);
        refreshEntity.setExpiration(date.toString());
        refreshRepository.save(refreshEntity);
    }
}
