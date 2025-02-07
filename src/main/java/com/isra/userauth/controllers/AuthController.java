package com.isra.userauth.controllers;

import com.isra.userauth.DTO.JwtResponse;
import com.isra.userauth.DTO.LoginRequest;
import com.isra.userauth.domain.GoogleUserInfo;
import com.isra.userauth.security.JwtTokenProvider;
import com.isra.userauth.services.AuthService;
import jakarta.security.auth.message.AuthException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthService authService;


    @PostMapping("/login")
    public ResponseEntity<JwtResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        JwtResponse jwtResponse = jwtTokenProvider.generateToken(authentication);

        return ResponseEntity.ok(jwtResponse);
    }

    @PostMapping("/google")
    public ResponseEntity<?> googleLogin(@RequestBody Map<String, String> request) {
        String code = request.get("code");

        try {
            String accessToken = authService.getGoogleAccessToken(code);
            GoogleUserInfo userInfo = authService.getGoogleUserInfo(accessToken);

            String jwtToken = jwtTokenProvider.generateTokenFromGoogle(userInfo);

            return ResponseEntity.ok(Map.of("token", jwtToken, "user", userInfo));
        } catch (AuthException e) {
            log.error("Erro na autenticação com o Google: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

}
