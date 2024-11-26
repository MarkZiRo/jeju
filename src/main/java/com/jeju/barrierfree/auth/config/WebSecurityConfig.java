package com.jeju.barrierfree.auth.config;

import com.jeju.barrierfree.auth.jwt.JwtTokenUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class WebSecurityConfig {

    private final JwtTokenUtils jwtTokenUtils;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        http
//                .cors(corsConfigure -> corsConfigure.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers(
                                        CustomReqeustMatchers.permitAllMatchers
                                )
                                .permitAll()
                                .anyRequest()
                                .permitAll()
                )
//                .oauth2Login(oauth2Login -> oauth2Login
//                        .loginPage("/login")
//                        .successHandler(oAuth2SuccessHandler)
//                        .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
//                )
//                .exceptionHandling(exceptions -> exceptions
//                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .sessionManagement(
                        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
//                .addFilterBefore(
//                        new JwtTokenFilter(jwtTokenUtils, manager), AuthorizationFilter.class
//                )
        ;
        return http.build();
    }

}