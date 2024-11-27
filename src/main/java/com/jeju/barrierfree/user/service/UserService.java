package com.jeju.barrierfree.user.service;

import com.jeju.barrierfree.auth.config.AuthenticationFacade;
import com.jeju.barrierfree.auth.jwt.JwtTokenUtils;
import com.jeju.barrierfree.user.Repository.UserRepository;
import com.jeju.barrierfree.user.dto.CreateUserDto;
import com.jeju.barrierfree.user.dto.UserDto;
import com.jeju.barrierfree.user.entity.UserEntity;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtils jwtTokenUtils;
    private final AuthenticationFacade authFacade;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                .map(CustomUserDetails::fromEntity)
                .orElseThrow(() -> new UsernameNotFoundException("not found"));
    }

    public UserDto createUser(CreateUserDto dto)
    {
        if(userRepository.existsByEmail(dto.getEmail()))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "email already exists");

        return UserDto.fromEntity(userRepository.save(UserEntity.builder()
                .email(dto.getEmail())
                .password(passwordEncoder.encode(dto.getPassword()))
                .username(dto.getName())
                .profileImage(dto.getProfileImage())
                .build()));
    }

}