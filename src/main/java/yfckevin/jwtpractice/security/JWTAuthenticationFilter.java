package yfckevin.jwtpractice.security;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import yfckevin.jwtpractice.util.JWTUtil;

import java.io.IOException;

import java.util.Optional;

// 繼承OncePerRequestFilter，代表每個request都會經過此filter
@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter{

    @Autowired
    private JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Optional
                .ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION))
                .filter(v -> v.startsWith("bearer "))
                .ifPresent(v -> {
                    final String userId = this.jwtUtil.verify(v.substring(7));
                    final UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                            new UsernamePasswordAuthenticationToken(userId, null, null);
                    usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                });

        filterChain.doFilter(request, response);
    }
}
