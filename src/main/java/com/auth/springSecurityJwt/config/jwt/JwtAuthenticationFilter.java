package com.auth.springSecurityJwt.config.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있는데
// /login에 username, password를 post로 요청하면 UUsernamePasswordAuthenticationFilter가 동작함
// 현재 formLogin().disable()을 했기 때문에 동작하지 않음
// 그러므로 직접 UsernamePasswordAuthenticationFilter를 만들어서 SecurityConfig에 등록시켜 동작시켜야 함.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // AuthenticationManager를 주입받아야 함
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter 로그인 시도중");

        // username과 password를 받아서 정상인지 로그인을 시도

        // authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출되고 loadUserByUsername() 함수가 실행됨

        // 그리고 PrincipalDetails를 세션에 담고 (세션에 담지 않으면 권한관리가 안됨) (내 의견: 뭔가 좀 이상함... 왜 JWT토큰을 사용하는데 권한까지 넣어버리면 될텐데 왜 세션에 담는건지...)

        // JWT토큰을 만들어서 응답해주면 됨

        return super.attemptAuthentication(request, response);
    }
}
