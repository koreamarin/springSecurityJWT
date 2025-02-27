package com.auth.springSecurityJwt.config.jwt;

import com.auth.springSecurityJwt.config.auth.PrincipalDetails;
import com.auth.springSecurityJwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.logging.Logger;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있는데
// /login에 username, password를 post로 요청하면 UUsernamePasswordAuthenticationFilter가 동작함
// 현재 formLogin().disable()을 했기 때문에 동작하지 않음
// 그러므로 직접 UsernamePasswordAuthenticationFilter를 만들어서 SecurityConfig에 등록시켜 동작시켜야 함.
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // AuthenticationManager를 주입받아야 함
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("JwtAuthenticationFilter 로그인 시도중");

        // username과 password를 받아서 정상인지 로그인을 시도
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            log.info(user.toString());

            // 이 authenticationToken은 임시로 Authentication 객체를 만들기 위한 것
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출되고 loadUserByUsername() 함수가 실행됨
            // loadUserByUsername() 함수가 실행된 후 정상이면 authentication 객체가 리턴됨
            // 이 객체가 만들어졌다는 것은 로그인이 정상적으로 되었다는 뜻. 즉 DB와 로그인한 username, password가 일치한다는 뜻
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication 객체에는 UserDetails 타입의 객체가 들어있음. 즉, 유저의 정보가 들어있음
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            log.info("로그인 성공 : " + principalDetails.getUser().getUsername());

            // 그리고 PrincipalDetails를 세션에 담고 (세션에 담지 않으면 권한관리가 안됨)
            // JWT를 사용하면서 세션을 만들 이유가 없지만 권한처리 때문에 세션에 넣어줌
            // 권한 관리를 Security에서 해주기 때문에 편하기 위해서 세션에 넣는 것임.
            return authentication;      // 이 리턴된 값이 세션에 저장됨
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // JWT토큰을 만들어서 응답해주면 됨
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
    // JWT토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻");

        super.successfulAuthentication(request, response, chain, authResult);
    }
}
