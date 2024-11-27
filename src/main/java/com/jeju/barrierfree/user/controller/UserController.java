package com.jeju.barrierfree.user.controller;

import com.jeju.barrierfree.user.dto.CreateUserDto;
import com.jeju.barrierfree.user.dto.UserDto;
import com.jeju.barrierfree.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("signup")
    public UserDto signUp(@RequestBody CreateUserDto dto)
    {
        return userService.createUser(dto);
    }
}
