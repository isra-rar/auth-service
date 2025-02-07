package com.isra.userauth.services;

import com.isra.userauth.domain.GoogleUserInfo;
import jakarta.security.auth.message.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final RestTemplate restTemplate;

    @Value("${google.client.id}")
    private String clientId;

    @Value("${google.client.secret}")
    private String clientSecret;

    @Value("${google.redirect.uri}")
    private String redirectUri;

    @Value("${google.url.tokenUrl}")
    private String tokenUrl;

    @Value("${google.url.userInfoUrl}")
    private String userInfoUrl;


    public String getGoogleAccessToken(String code) throws AuthException {
        Map<String, String> params = Map.of(
                "code", code,
                "client_id", clientId,
                "client_secret", clientSecret,
                "redirect_uri", redirectUri,
                "grant_type", "authorization_code"
        );

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, params, Map.class);
            return response.getBody().get("access_token").toString();
        } catch (Exception e) {
            log.error("Erro ao obter access token do Google: {}", e.getMessage());
            throw new AuthException("Erro ao autenticar com o Google");
        }
    }

    public GoogleUserInfo getGoogleUserInfo(String accessToken) throws AuthException {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<GoogleUserInfo> response = restTemplate.exchange(
                    userInfoUrl, HttpMethod.GET, entity, GoogleUserInfo.class
            );
            return response.getBody();
        } catch (Exception e) {
            log.error("Erro ao obter informações do usuário: {}", e.getMessage());
            throw new AuthException("Erro ao obter informações do usuário");
        }
    }
}
