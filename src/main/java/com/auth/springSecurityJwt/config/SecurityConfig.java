package com.auth.springSecurityJwt.config;

import com.auth.springSecurityJwt.filter.MyFilter1;
import com.auth.springSecurityJwt.filter.MyFilter3;
import com.auth.springSecurityJwt.filter.MyFilter4;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CorsFilter corsFilter;

    public SecurityConfig(CorsFilter corsFilter) {
        this.corsFilter = corsFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); //  SecurityContextPersistenceFilter이 시작되기 전에 MyFilter3를 실행하겠다는 뜻
        http.addFilterAfter(new MyFilter4(), SecurityContextPersistenceFilter.class); //  SecurityContextPersistenceFilter이 시작되기 전에 MyFilter4를 실행하겠다는 뜻

        http
                .csrf(AbstractHttpConfigurer::disable)         // csrf 비활성화
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  // 세선을 사용하지 않겠다는 설정
                .formLogin(AbstractHttpConfigurer::disable)    // 폼 로그인 비활성화
                .httpBasic(AbstractHttpConfigurer::disable)    // http Basic 인증 비활성화
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/api/v1/user/**")
                        .hasAnyAuthority("ROLE_USER", "ROLE_MANAGER", "ROLE_ADMIN")
                    .requestMatchers("/api/v1/manager/**")
                        .hasAnyAuthority( "ROLE_MANAGER", "ROLE_ADMIN")
                    .requestMatchers("/api/v1/admin/**")
                        .hasAnyAuthority("ROLE_ADMIN")
                    .anyRequest().permitAll()
                )
                .addFilter(corsFilter)      // 커스텀한 Cors 필터 추가하여 Cors정책을 새로 만들어 넣음
        ;

        return http.build();
    }
}
