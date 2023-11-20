package com.example.teama.jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
public class JwtTokenizer {     // JWT를 생성하고 검증하는데 사용되는 유틸리티 클래스
    private final byte[] accessSecret;
    private final byte[] refreshSecret;

    public final static Long ACCESS_TOKEN_EXPIRE_COUNT = 30 * 60 * 1000L; // 30 minutes
    public final static Long REFRESH_TOKEN_EXPIRE_COUNT = 7 * 24 * 60 * 60 * 1000L; // 7 days

    public JwtTokenizer(@Value("${jwt.secretKey}") String accessSecret, @Value("${jwt.refreshKey}") String refreshSecret) {
        this.accessSecret = accessSecret.getBytes(StandardCharsets.UTF_8);
        this.refreshSecret = refreshSecret.getBytes(StandardCharsets.UTF_8);
    }

    // AccessToken 생성
    public String createAccessToken(Long id, String email, String name, List<String> roles) {
        return createToken(id, email, name, roles, ACCESS_TOKEN_EXPIRE_COUNT, accessSecret);
    }

    // RefreshToken 생성
    public String createRefreshToken(Long id, String email, String name, List<String> roles) {
        return createToken(id, email, name, roles, REFRESH_TOKEN_EXPIRE_COUNT, refreshSecret);
    }

    // AccessToken 및 RefreshToken을 생성
    private String createToken(Long id, String email, String name, List<String> roles,
                               Long expire, byte[] secretKey) {
        // 토큰의 클레임(클레임은 토큰에 담기는 정보)을 설정
        Claims claims = Jwts.claims().setSubject(email);

        claims.put("roles", roles);
        claims.put("id", id);
        claims.put("name", name);

        // 위의 클레임을 기반으로 Token 생성
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + expire))
                .signWith(getSigningKey(secretKey))
                .compact();
    }

    // Token에서 User Id 얻기
    public Long getUserIdFromToken(String token) {
        String[] tokenArr = token.split(" ");
        token = tokenArr[1];
        Claims claims = parseToken(token, accessSecret);
        return Long.valueOf((Integer)claims.get("id"));
    }

    // 주어진 AccessToken을 분석하고 해당하는 클레임을 반환
    public Claims parseAccessToken(String accessToken) {
        return parseToken(accessToken, accessSecret);
    }

    // 주어진 RefreshToken을 분석하고 해당하는 클레임을 반환
    public Claims parseRefreshToken(String refreshToken) {
        return parseToken(refreshToken, refreshSecret);
    }

    // 주어진 Token을 분석하고 해당하는 클레임을 반환
    public Claims parseToken(String token, byte[] secretKey) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey(secretKey))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * @param secretKey - byte형식
     * @return Key 형식 시크릿 키
     * 주어진 시크릿 키의 바이트 배열을 사용하여 서명 키를 생성
     * JWT 라이브러리의 Keys.hmacShaKeyFor 메서드를 사용하여 서명 키를 생성
     */
    public static Key getSigningKey(byte[] secretKey) {
        return Keys.hmacShaKeyFor(secretKey);
    }

}
