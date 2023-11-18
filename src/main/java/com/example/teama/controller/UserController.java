package com.example.teama.controller;

import com.example.teama.dto.user.*;
import com.example.teama.entity.RefreshToken;
import com.example.teama.entity.Role;
import com.example.teama.entity.User;
import com.example.teama.jwt.util.IfLogin;
import com.example.teama.jwt.util.JwtTokenizer;
import com.example.teama.jwt.util.LoginUserDto;
import com.example.teama.service.RefreshTokenService;
import com.example.teama.service.UserService;
import io.jsonwebtoken.Claims;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@Validated
@RequestMapping("/users")
@Slf4j
public class UserController {

    private final JwtTokenizer jwtTokenizer;
    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;


//    내 정보 조회
    @PostMapping("/myinfo")
    public User showMyInfo(@IfLogin LoginUserDto loginUserDto, @RequestParam(required = false) String userEmail){


        User user= userService.findByEmail(loginUserDto.getUserEmail());

        log.info(loginUserDto.getUserEmail());


        return user;
    }





//        // 회원가입
    @PostMapping("/signup")
    public ResponseEntity signup(@RequestBody @Valid UserSignupDto userSignupDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        User user = User.builder()
                .userEmail(userSignupDto.getUserEmail())
                .userPassword(passwordEncoder.encode(userSignupDto.getUserPassword()))
                .userNickname(userSignupDto.getUserNickname())
                .userPhone(userSignupDto.getUserPhone())
                .build();


        User saveUser = userService.addUser(user);

        UserSignupResponseDto userSignupResponse = new UserSignupResponseDto();
        userSignupResponse.setId(saveUser.getId());
        userSignupResponse.setUserNickname(saveUser.getUserNickname());
        userSignupResponse.setUserEmail(saveUser.getUserEmail());


        return new ResponseEntity(userSignupResponse, HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody @Valid UserLoginDto loginDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        // email이 없을 경우 Exception이 발생한다. Global Exception에 대한 처리가 필요하다.
        User user = userService.findByEmail(loginDto.getUserEmail());
        if(!passwordEncoder.matches(loginDto.getUserPassword(), user.getUserPassword())){
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

        List<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());

        // JWT토큰을 생성하였다. jwt라이브러리를 이용하여 생성.

        String accessToken = jwtTokenizer.createAccessToken(user.getId(), user.getUserEmail(), user.getUserPassword(), roles);
        String refreshToken = jwtTokenizer.createRefreshToken(user.getId(), user.getUserEmail(), user.getUserPassword(), roles);

//         RefreshToken을 DB에 저장한다. 성능 때문에 DB가 아니라 Redis에 저장하는 것이 좋다.


        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setValue(refreshToken);
//        refreshTokenEntity.setMemberId(user.getId());
        refreshTokenEntity.setUser(user);
        refreshTokenService.addRefreshToken(refreshTokenEntity);



        UserLoginResponseDto loginResponse = UserLoginResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .id(user.getId())
                .userNickname(user.getUserNickname())
                .build();
        log.info("로그인 완료");


        return new ResponseEntity(loginResponse, HttpStatus.OK);




    }

//   로그아웃
    @DeleteMapping("/logout")
    public ResponseEntity logout(@RequestBody RefreshTokenDto refreshTokenDto) {
        refreshTokenService.deleteRefreshToken(refreshTokenDto.getRefreshToken());
        log.info("들어옴");
        log.info(refreshTokenDto.getRefreshToken());
        return new ResponseEntity(HttpStatus.OK);
    }



    /*
    1. 전달받은 유저의 아이디로 유저가 존재하는지 확인한다.
    2. RefreshToken이 유효한지 체크한다.
    3. AccessToken을 발급하여 기존 RefreshToken과 함께 응답한다.
     */


    //refreshToken 으로 accessToken 재발급
    @PostMapping("/refreshToken")
    public ResponseEntity requestRefresh(@RequestBody RefreshTokenDto refreshTokenDto) {
        RefreshToken refreshToken = refreshTokenService.findRefreshToken(refreshTokenDto.getRefreshToken()).orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));
        Claims claims = jwtTokenizer.parseRefreshToken(refreshToken.getValue());

        Long id = Long.valueOf((Integer)claims.get("id"));

        User user = userService.getUser(id).orElseThrow(() -> new IllegalArgumentException("User not found"));


        // List<Role> ===> List<String> 으로 변경
        List roles = (List) claims.get("roles");
        String email = claims.getSubject();

        String accessToken = jwtTokenizer.createAccessToken(id, email, user.getUserNickname(), roles);


        UserLoginResponseDto loginResponse = UserLoginResponseDto.builder()
                .accessToken(accessToken)
                //.refreshToken(refreshTokenDto.getRefreshToken())
                .id(user.getId())
                .userNickname(user.getUserNickname())
                .build();
        return new ResponseEntity(loginResponse, HttpStatus.OK);
    }

    @GetMapping("/info")
    public ResponseEntity userinfo(@IfLogin LoginUserDto loginUserDto) {
        User user = userService.findByEmail(loginUserDto.getUserEmail());
        return new ResponseEntity(user, HttpStatus.OK);
    }

}


