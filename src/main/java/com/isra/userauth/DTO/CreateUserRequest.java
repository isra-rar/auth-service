package com.isra.userauth.DTO;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CreateUserRequest {


    private String firstName;

    private String lastName;

    private String username;

    private String email;

    private String password;

    private String passwordConfirm;


}
