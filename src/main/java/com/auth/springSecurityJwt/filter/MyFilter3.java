package com.auth.springSecurityJwt.filter;


import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 클라이언트가 요청을 할때마다 보내오는
        // header에서 authrorization에서 토큰을 추출하여 내가 만든 토큰이 맞는지 확인하는 과정 (RSA, HS256)
        // id, pw가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 응답을 해주는 과정을 먼저 거쳐야 한다.
        if(req.getMethod().equals("POST")) {
            String headerAuth = req.getHeader("Authorization");
            System.out.println("headerAuth : " + headerAuth);
            System.out.println("필터3");

            if(headerAuth.equals("cos")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }
    }
}
