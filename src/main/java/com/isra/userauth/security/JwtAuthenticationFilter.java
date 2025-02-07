package com.isra.userauth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String TOKEN_PREFIX = "Bearer ";

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, UserDetailsService userDetailsService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        extractTokenFromHeader(request.getHeader("Authorization"))
                .filter(token -> SecurityContextHolder.getContext().getAuthentication() == null)
                .filter(jwtTokenProvider::isTokenValid) // Usa a validação direta
                .map(jwtTokenProvider::getUsernameFromToken)
                .map(userDetailsService::loadUserByUsername)
                .ifPresent(userDetails -> setAuthentication(userDetails, request));

        filterChain.doFilter(request, response);
    }

    private Optional<String> extractTokenFromHeader(String header) {
        return (header != null && header.startsWith(TOKEN_PREFIX))
                ? Optional.of(header.substring(TOKEN_PREFIX.length()))
                : Optional.empty();
    }

    private void setAuthentication(UserDetails userDetails, HttpServletRequest request) {
        List<SimpleGrantedAuthority> authorities = getAuthoritiesFromToken(userDetails.getUsername());

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private List<SimpleGrantedAuthority> getAuthoritiesFromToken(String token) {
        String roles = jwtTokenProvider.getRolesFromToken(token);
        return Stream.of(roles.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
