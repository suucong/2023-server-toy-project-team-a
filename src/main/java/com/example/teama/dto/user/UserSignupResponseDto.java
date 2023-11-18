package com.example.teama.dto.user;

import lombok.Data;


@Data
public class UserSignupResponseDto {
    private Long id;
    private String userEmail;
    private String userNickname;
}
