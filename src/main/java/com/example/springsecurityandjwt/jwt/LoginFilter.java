package com.example.springsecurityandjwt.jwt;

import com.example.springsecurityandjwt.dto.CustomUserDetails;
import com.example.springsecurityandjwt.dto.LoginDto;
import com.example.springsecurityandjwt.entity.RefreshEntity;
import com.example.springsecurityandjwt.repository.RefreshRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

@AllArgsConstructor
@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        /*
        String userName = obtainUsername(request);
        String password = obtainPassword(request);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userName, password, null);
        return authenticationManager.authenticate(authenticationToken);
        */
        LoginDto loginDto = new LoginDto();
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            ServletInputStream inputStream = request.getInputStream();
            String messageBody = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
            loginDto = objectMapper.readValue(messageBody, LoginDto.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        log.info("userId : {}", loginDto.getUserId());
        String userId = loginDto.getUserId();
        String password = loginDto.getPassword();
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userId, password, null);
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
        /*CustomUserDetails customUserDetails = (CustomUserDetails)authentication.getPrincipal();
        String userId = customUserDetails.getUsername();
        Collection<? extends GrantedAuthority> authorities = customUserDetails.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority grantedAuthority = iterator.next();
        String role = grantedAuthority.getAuthority();
        String jwt = jwtUtil.createJwt(userId, role, 60*60*1000L);
        log .info("jwt : {}", jwt);
        response.addHeader("Authorization", "Bearer " + jwt); // 띄어쓰기 무조건 있어야 한다 RFC 7235 인증방식이 이 형태를 요구하기 때문*/
        //유저 정보
        String userId = authentication.getName();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority grantedAuthority = iterator.next();
        String role = grantedAuthority.getAuthority();
        //토큰 생성
        String accessToken = jwtUtil.createJwt("access", userId, role, 600000L);
        String refreshToken = jwtUtil.createJwt("refresh", userId, role, 86400000L);
        log.info("access token : {}", accessToken);
        log.info("refresh token : {}",refreshToken);
        //리프레시 토큰 저장
        addRefreshToken(userId, refreshToken, 86400000L);
        //응답 설정
        response.setHeader("access-token", accessToken);
        response.addCookie(createCookie("refresh-token", refreshToken));
        response.setStatus(HttpServletResponse.SC_OK);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private Cookie createCookie(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(24* 60 * 60);
        //cookie.setPath("/");
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
