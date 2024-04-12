package com.security.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.security.security.service.JwtService;
import com.security.security.service.MyUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// this filter has to be called for all request
@Component
public class JwtFilter extends OncePerRequestFilter{

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ApplicationContext context;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

            String authHeader=request.getHeader("Authorization");
            String token=null;
            String username=null;

            if(authHeader!=null && authHeader.startsWith("Bearer ")){
                token=authHeader.substring(7);
                username=jwtService.extractUserName(token);

            }

            //check name is not null 
            //check if already authentiacated object do exist than no need of auth
            if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
                //validate token
                //update authtication object for spring security with jwt
                UserDetails userdetails=context.getBean(MyUserDetailsService.class).loadUserByUsername(username)

                if(jwtService.validateToken(token,userdetails)){
                    UsernamePasswordAuthenticationToken authToken=new UsernamePasswordAuthenticationToken(userdetails,null,userdetails.getAuthorities());

                    //token should also know what request object has
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                     //set token to SecurityContextHolder.getContext().getAuthentication()
                     SecurityContextHolder.getContext().setAuthentication(authToken);
                }

            }
            //continue filterchain
            filterChain.doFilter(request, response);

    }

}
