package com.isra.userauth.services;

import com.isra.userauth.DTO.CreateUserRequest;
import com.isra.userauth.domain.Usuario;
import com.isra.userauth.repositories.RolesRepository;
import com.isra.userauth.repositories.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UsuarioRepository usuarioRepository;
    private final RolesRepository rolesRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;

    public void createUser(CreateUserRequest createUserRequest) {
        Usuario usuario = modelMapper.map(createUserRequest, Usuario.class);
        setEncryptPassword(createUserRequest, usuario);
        setUserRole(usuario);
        usuarioRepository.save(usuario);
    }

    private void setUserRole(Usuario usuario) {
        rolesRepository.findByName("ROLE_USER").ifPresent(role -> usuario.setRoles(Set.of(role)));
    }

    private void setEncryptPassword(CreateUserRequest createUserRequest, Usuario usuario) {
        usuario.setPassword(passwordEncoder.encode(createUserRequest.getPassword()));
    }
}
