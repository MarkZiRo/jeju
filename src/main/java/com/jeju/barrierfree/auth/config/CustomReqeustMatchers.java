package com.jeju.barrierfree.auth.config;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class CustomReqeustMatchers {

    public static RequestMatcher[] permitAllMatchers ={

            AntPathRequestMatcher.antMatcher(HttpMethod.GET, "/exception/**"),
            AntPathRequestMatcher.antMatcher(HttpMethod.POST, "/users/**"),
            AntPathRequestMatcher.antMatcher("/"),
            AntPathRequestMatcher.antMatcher("/oauth2"),
            AntPathRequestMatcher.antMatcher("/swagger-ui/**"),
            AntPathRequestMatcher.antMatcher("/swagger-resources/**"),
            AntPathRequestMatcher.antMatcher("/login"),
            AntPathRequestMatcher.antMatcher("/api/v1/image/**")

    };
}
