package com.example.teama.jwt.util;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginInfoDto {
    private Long userId;
    private String email;
    private String userNickname;
}
