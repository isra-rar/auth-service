package com.isra.userauth.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/usuarios")
public class UsuarioController {

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
}
