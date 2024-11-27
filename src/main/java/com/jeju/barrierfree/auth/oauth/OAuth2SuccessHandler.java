package com.jeju.barrierfree.auth.oauth;

import com.jeju.barrierfree.auth.jwt.JwtTokenUtils;
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

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenUtils tokenUtils;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

       OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = oAuth2User.getAttribute("email");
        String provider = oAuth2User.getAttribute("provider");
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

        // JWT 생성
        String jwt = tokenUtils.generateToken(details);

    }

}
