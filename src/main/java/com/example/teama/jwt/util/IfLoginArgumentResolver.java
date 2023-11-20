package com.example.teama.jwt.util;

import com.example.teama.jwt.token.JwtAuthenticationToken;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.Collection;
import java.util.Iterator;

/* 컨트롤러 메서드의 파라미터에 @IfLogin 어노테이션이 사용되면 이를 처리하는 역할
   @IfLogin 어노테이션이 적용된 파라미터가 컨트롤러 메서드에서 사용될 때, 사용자의 인증 정보를 주입하는 역할 */
public class IfLoginArgumentResolver implements HandlerMethodArgumentResolver {
    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        /* @IfLogin 어노테이션이 파라미터에 존재하고,
           파라미터의 타입이 LoginUserDto인 경우에만 true를 반환 */
        return parameter.getParameterAnnotation(IfLogin.class) != null
                && parameter.getParameterType() == LoginUserDto.class;
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        Authentication authentication = null;
        try {
            //  Spring Security의 SecurityContextHolder에서 Authentication을 가져오고, 이를 통해 사용자가 인증되었는지 확인
            authentication = SecurityContextHolder.getContext().getAuthentication();
        } catch (Exception ex) {
            // 사용자가 인증되어 있지 않으면 null을 반환
            return null;
        }
        if (authentication == null) {
            return null;
        }

        // JwtAuthenticationToken에서 사용자 정보를 추출하여 LoginUserDto 객체를 생성하고 반환
        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken)authentication;
        LoginUserDto loginUserDto = new LoginUserDto();

        Object principal = jwtAuthenticationToken.getPrincipal(); // LoginInfoDto
        if (principal == null)
            return null;

        LoginInfoDto loginInfoDto = (LoginInfoDto)principal;
        loginUserDto.setUserEmail(loginInfoDto.getEmail());
        loginUserDto.setUserId(loginInfoDto.getUserId());
        loginUserDto.setUserNickname(loginInfoDto.getUserNickname());

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        while (iterator.hasNext()) {
            GrantedAuthority grantedAuthority = iterator.next();
            String role = grantedAuthority.getAuthority();
            loginUserDto.addRole(role);
        }

        return loginUserDto;
    }
}

