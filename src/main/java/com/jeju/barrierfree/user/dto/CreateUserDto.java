package com.jeju.barrierfree.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateUserDto {

    private String email;
    private String password;
    private String name;
    private String profileImage;

}
