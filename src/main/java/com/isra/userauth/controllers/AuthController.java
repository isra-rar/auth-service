package com.isra.userauth.controllers;

import com.isra.userauth.DTO.ApiResponse;
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
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthService authService;


    @PostMapping("/login")
    public ResponseEntity<ApiResponse<JwtResponse>> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        JwtResponse jwtResponse = jwtTokenProvider.generateToken(authentication);

        return ResponseEntity.ok(new ApiResponse<>(true, "Login successful", jwtResponse));
    }

    @GetMapping("/google")
    public ResponseEntity<?> googleLogin(@RequestParam String code) {
        try {
            String accessToken = authService.getGoogleAccessToken(code);
            GoogleUserInfo userInfo = authService.getGoogleUserInfo(accessToken);

            String jwtToken = jwtTokenProvider.generateTokenFromGoogle(userInfo);

            String frontendCallbackUrl = "http://localhost:4200/auth/callback?token=" + jwtToken;

            // Redirecionamento com o token na URL
            return ResponseEntity.status(HttpStatus.FOUND).header("Location", frontendCallbackUrl).build();

        } catch (AuthException e) {
            log.error("Erro na autenticação com o Google: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

}
