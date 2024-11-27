package com.jeju.barrierfree.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;
import com.jeju.barrierfree.user.entity.UserEntity;

import java.security.Key;
import java.time.Instant;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenUtils {

    private final Key signingKey;
    private final JwtParser jwtParser;

    private static final long ACCESS_TOKEN_EXPIRE_TIME = 60 * 60L;

    private static final long REFRESH_TOKEN_EXPIRE_TIME = 60 * 60 * 24 * 14L;

    public String generateAccessToken(UserEntity userDetails)
    {
        return generateToken(userDetails, ACCESS_TOKEN_EXPIRE_TIME);
    }

    public String generateRefreshToken(UserEntity userDetails)
    {
        return generateToken(userDetails, REFRESH_TOKEN_EXPIRE_TIME);
    }



    public JwtTokenUtils(@Value("${jwt.secret}") String jwtSecret) {
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        this.jwtParser = Jwts.parserBuilder().setSigningKey(this.signingKey).build();
    }

    public String generateToken(UserEntity userDetails, long expireTime) {
        Instant now = Instant.now();
        Claims jwtClaims = Jwts.claims()
                .setSubject(userDetails.getEmail())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(expireTime)));

        jwtClaims.put("type", expireTime == ACCESS_TOKEN_EXPIRE_TIME ? "access" : "refresh");

        return Jwts.builder()
                .setClaims(jwtClaims)
                .signWith(this.signingKey)
                .compact();
    }

    public boolean validate(String token) {
        try {
            jwtParser.parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            log.warn("invalid jwt");
        }
        return false;
    }

    public Claims parseClaims(String token)
    {
        return jwtParser
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isAccessToken(String token)
    {
        Claims claims = parseClaims(token);
        return "access".equals(claims.get("type"));
    }

}
