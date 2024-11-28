package com.jeju.barrierfree.auth.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jeju.barrierfree.auth.jwt.JwtResponseDto;
import com.jeju.barrierfree.auth.jwt.JwtTokenUtils;
import com.jeju.barrierfree.auth.repository.RefreshTokenRepository;
import com.jeju.barrierfree.user.dto.UserDto;
import com.jeju.barrierfree.user.entity.UserEntity;
import com.jeju.barrierfree.user.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenUtils tokenUtils;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

       OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = oAuth2User.getAttribute("email");
        String username
                = oAuth2User.getAttribute("nickname");
        String providerId = oAuth2User.getAttribute("id").toString();
        String profileImage = oAuth2User.getAttribute("profileImg").toString();

        if(!userService.existsByEmail(email))
        {
            userService.createOAuth2User(UserDto.builder()
                    .email(email)
                    .password(passwordEncoder.encode(providerId))
                    .profileImage(profileImage)
                    .username(username)
                    .build());
        }

        UserEntity details
                = userService.loadUserByEmail(email);

        String accessToken = tokenUtils.generateAccessToken(details);
        String refreshToken = tokenUtils.generateRefreshToken(details);

//        refreshTokenRepository.save(email, refreshToken);

        // 응답 데이터 생성
        JwtResponseDto responseDto = new JwtResponseDto();
        responseDto.setAccessToken(accessToken);
        responseDto.setRefreshToken(refreshToken);
        responseDto.setAccessTokenExpiresIn(System.currentTimeMillis() + (60 * 60 * 1000));

                // 프론트를 위한 리다이렉트 url
        String targetUrl = UriComponentsBuilder.fromUriString("/oauth2/success")
                .queryParam("accessToken", accessToken)
                .queryParam("refreshToken", refreshToken)
                .build().toUriString();

        if (isAjax(request)) {
            // AJAX 요청인 경우 JSON 응답
            response.getWriter().write(objectMapper.writeValueAsString(responseDto));
        } else {
            // 일반 요청인 경우 리다이렉트
            response.sendRedirect(targetUrl);
        }
    }

    private boolean isAjax(HttpServletRequest request) {
        String headerValue = request.getHeader("X-Requested-With");
        return "XMLHttpRequest".equals(headerValue);
    }
}


