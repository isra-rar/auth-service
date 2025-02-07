package com.isra.userauth.DTO;


import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequest {

    @NotBlank(message = "O nome de usuário não pode estar vazio")
    private String username;

    @NotBlank(message = "A senha não pode estar vazia")
    private String password;
}
