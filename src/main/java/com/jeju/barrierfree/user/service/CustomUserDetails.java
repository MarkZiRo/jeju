package com.jeju.barrierfree.user.service;

import com.jeju.barrierfree.user.entity.UserEntity;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@ToString
public class CustomUserDetails implements UserDetails {

    private Long id;
    private String email;
    private String username;
    private String password;
    private String authorities;
    private String profileImage;

    @Getter
    private UserEntity entity;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.stream(authorities.split(","))
                .sorted()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    public static CustomUserDetails fromEntity(UserEntity entity)
    {
        return CustomUserDetails.builder()
                .entity(entity)
                .build();
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public UserEntity toUserEntity()
    {
        return UserEntity.builder()
                .id(id)
                .username(username)
                .password(password)
                .email(email)
                .profileImage(profileImage)
                .authorities(authorities)
                .build();
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }


}
