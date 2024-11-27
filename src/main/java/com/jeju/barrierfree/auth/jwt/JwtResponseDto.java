package com.jeju.barrierfree.auth.jwt;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JwtResponseDto {

    private String accessToken;
    private String refreshToken;
    private long accessTokenExpiresIn;
}
