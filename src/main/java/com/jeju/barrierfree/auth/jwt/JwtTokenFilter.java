package com.jeju.barrierfree.auth.jwt;

import com.jeju.barrierfree.user.service.CustomUserDetails;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.http.HttpHeaders;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

    private final JwtTokenUtils jwtTokenUtils;
    private final UserDetailsService service;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(authHeader != null && authHeader.startsWith("Bearer"))
        {
            String token = authHeader.split(" ")[1];

            if(jwtTokenUtils.validate(token) && jwtTokenUtils.isAccessToken(token))
            {
                SecurityContext context = SecurityContextHolder.createEmptyContext();

                String email = jwtTokenUtils.parseClaims(token).getSubject();

                Claims jwtClaims = jwtTokenUtils.parseClaims(token);

                UserDetails userDetails = service.loadUserByUsername(email);

                AbstractAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                token
                        );

                context.setAuthentication(authenticationToken);
                SecurityContextHolder.setContext(context);
                log.info("username: {}" , ((CustomUserDetails)userDetails).getEntity());
                log.info("set security context with jwt");
            }
            else {
                log.warn("jwt validation failed");
            }
        }
        filterChain.doFilter(request,response);
    }
}
