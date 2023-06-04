package yfckevin.jwtpractice.security;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import yfckevin.jwtpractice.service.AuthService;
import yfckevin.jwtpractice.util.JWTUtil;

import java.io.IOException;

import java.util.Optional;

// 繼承OncePerRequestFilter，代表每個request都會經過此filter
@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter{


    private JWTUtil jwtUtil;
    private AuthService authService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String jwt;
        final String userEmail;

        if(authHeader == null || !authHeader.startsWith("bearer ")){
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        userEmail = jwtUtil.verify(jwt);

        // 如果有傳入email且尚未經過驗證(Authentication)
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            // 帶入email去資料庫取出userDetails
            UserDetails userDetails = this.authService.loadUserByUsername(userEmail);
            // 再來檢核userDetails中的userEmail是否相同，且token是否過期
            if(jwtUtil.isTokenValid(jwt, userDetails)){
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                usernamePasswordAuthenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
