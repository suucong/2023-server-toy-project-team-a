// 패키지 및 클래스 선언부
package com.example.teama.config;

import com.example.teama.jwt.exception.CustomAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

// Spring Security 설정 클래스
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    // 의존성 주입을 위한 롬복의 RequiredArgsConstructor 어노테이션 사용
    private final AuthenticationManagerConfig authenticationManagerConfig;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    // SecurityFilterChain 빈 등록
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // 세션 관리 정책 설정 (STATELESS: 세션 사용하지 않음)
                .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 폼 로그인 비활성화 직접 id, password 를 입력받아서 jwt 토큰을 리턴하는 api 를 직접 만든다
                .formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer.disable())
                // CSRF 보안 비활성화 Cross Site Request Forgery의 약자. CSRF 공격을 막기 위한 방법
                .csrf(csrf -> csrf.disable())
                // CORS 설정 활성화
                .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()))
                // HTTP Basic 인증 비활성화
                .httpBasic(httpSecurityHttpBasicConfigurer -> httpSecurityHttpBasicConfigurer.disable())
                // 요청 권한 설정
                .authorizeHttpRequests(httpRequests -> httpRequests
                        .requestMatchers(CorsUtils::isPreFlightRequest).permitAll() // Preflight 요청은 허용 , 사전 인증이라는 요청 방식은 허용하겠다
                        .requestMatchers(new AntPathRequestMatcher("/users/signup")
                                , new AntPathRequestMatcher("/users/login")
                                , new AntPathRequestMatcher("/users/info")).permitAll()

                        .requestMatchers(new AntPathRequestMatcher("/users/myinfo")).hasRole("USER")
                        .requestMatchers(new AntPathRequestMatcher("/users/logout")).permitAll()

                )
                    //    .requestMatchers(new AntPathRequestMatcher(POST,"/**").hasAnyRole("USER", "ADMIN"))


//                        .requestMatchers( "/users/signup", "/users/login").permitAll() // 권한이 있든 없든 누구나 접근 가능
//                       // .requestMatchers(GET, "/categories/**", "/products/**").permitAll() // 특정 HTTP 메서드 및 URL 패턴은 누구나 접근 가능
//                        .requestMatchers(GET,"/**").hasAnyRole( "USER") // 특정 HTTP 메서드는 USER 역할이 있는 사용자만 접근 가능
//                        .requestMatchers(POST,"/**").hasAnyRole("USER", "ADMIN") // 특정 HTTP 메서드는 USER 또는 ADMIN 역할이 있는 사용자만 접근 가능
//                        .anyRequest().hasAnyRole("USER", "ADMIN")) // 그 외의 요청은 USER 또는 ADMIN 역할이 있는 사용자만 접근 가능
                // 예외 처리 설정
                .exceptionHandling(httpSecurityExceptionHandlingConfigurer -> httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(customAuthenticationEntryPoint))
                // 추가적인 설정을 적용하는데 사용한 AuthenticationManagerConfig 빈을 적용
                .apply(authenticationManagerConfig);

        return httpSecurity.build();
    }

    // CORS 설정을 위한 CorsConfigurationSource 빈 등록
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("*");
        config.addAllowedMethod("*");
        config.setAllowedMethods(List.of("GET","POST","DELETE","PATCH","OPTION","PUT"));
        source.registerCorsConfiguration("/**", config);

        return source;
    }

    // 패스워드 인코딩을 위한 PasswordEncoder 빈 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

/*
BCrypt는 비밀번호를 안전하게 저장하기 위한 해시 함수입니다.
BCrypt는 비밀번호 해싱을 위해 Blowfish 암호화 알고리즘을 사용하며, 암호화된 비밀번호를 저장할 때 임의의 솔트(salt)를 생성하여 비밀번호의 보안성을 높입니다.

BCrypt는 강력한 암호화 알고리즘을 사용하기 때문에 해독이 거의 불가능합니다.
이는 해커가 데이터베이스를 공격하여 해시된 비밀번호를 복원하는 것을 어렵게 만듭니다.
또한, BCrypt는 더 높은 수준의 보안성을 위해 비밀번호를 반복해서 해싱하는 기능(최소 10회 이상)을 지원합니다.

BCrypt는 Java, Ruby, Python, C#, PHP 등 다양한 프로그래밍 언어에서 사용할 수 있으며,
많은 웹 프레임워크에서 기본적으로 BCrypt를 지원하고 있습니다.
비밀번호를 안전하게 저장하기 위해서는 BCrypt와 같은 안전한 해시 함수를 사용하는 것이 좋습니다.
*/
