package com.jeju.barrierfree.auth.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;
import java.util.concurrent.TimeUnit;

@Repository
@RequiredArgsConstructor
public class RefreshTokenRepository {

    private final RedisTemplate<String, String> redisTemplate;
    private final static long REFRESH_TOKEN_EXPIRE_TIME = 60 * 60 * 24 * 14L;

    public void save(String email, String refreshToken)
    {
        redisTemplate.opsForValue()
                .set(email, refreshToken, REFRESH_TOKEN_EXPIRE_TIME, TimeUnit.SECONDS);
    }

    public String findByEmail(String email)
    {
        return redisTemplate.opsForValue().get(email);
    }

    public void deleteByEmail(String email)
    {
        redisTemplate.delete(email);
    }
}
