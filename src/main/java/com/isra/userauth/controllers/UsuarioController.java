package com.isra.userauth.controllers;

import com.isra.userauth.DTO.CreateUserRequest;
import com.isra.userauth.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/users")
@RequiredArgsConstructor
public class UsuarioController {

    private final UserService userService;

    @GetMapping
    @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
    public String getAllEmployees(){
        return "You Received All Employees List";
    }

    @PostMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String saveEmployees(){
        return "You saved a Employee";
    }

    @PutMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String updateEmployees(){
        return "You updated a Employee";
    }

    @PostMapping("/create")
    public ResponseEntity<Void> createEmployee(@RequestBody CreateUserRequest createUserRequest){
        userService.createUser(createUserRequest);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

}
