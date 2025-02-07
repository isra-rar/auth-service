package com.isra.userauth.util;

import com.isra.userauth.domain.Roles;
import com.isra.userauth.domain.Usuario;
import com.isra.userauth.repositories.RolesRepository;
import com.isra.userauth.repositories.UsuarioRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class DataLoader implements CommandLineRunner {

    private final UsuarioRepository usuarioRepository;
    private final RolesRepository rolesRepository;
    private final PasswordEncoder passwordEncoder;


    public DataLoader(UsuarioRepository usuarioRepository, RolesRepository rolesRepository, PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.rolesRepository = rolesRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        // Criar e salvar roles
        if (rolesRepository.count() == 0) {
            Roles adminRole = new Roles();
            adminRole.setName("ROLE_ADMIN");
            rolesRepository.save(adminRole);

            Roles userRole = new Roles();
            userRole.setName("ROLE_USER");
            rolesRepository.save(userRole);
        }

        // Criar e salvar usuários
        if (usuarioRepository.count() == 0) {
            Set<Roles> adminRoles = new HashSet<>();
            adminRoles.add(rolesRepository.findByName("ROLE_ADMIN").orElseThrow(() -> new RuntimeException("Role not found")));
            adminRoles.add(rolesRepository.findByName("ROLE_USER").orElseThrow(() -> new RuntimeException("Role not found")));

            Usuario adminUser = new Usuario();
            adminUser.setUsername("admin");
            adminUser.setEmail("admin@example.com");
            adminUser.setPassword(passwordEncoder.encode("adminpassword"));
            adminUser.setRoles(adminRoles);
            usuarioRepository.save(adminUser);

            Set<Roles> userRoles = new HashSet<>();
            userRoles.add(rolesRepository.findByName("ROLE_USER").orElseThrow(() -> new RuntimeException("Role not found")));

            Usuario regularUser = new Usuario();
            regularUser.setUsername("user");
            regularUser.setEmail("user@example.com");
            regularUser.setPassword(passwordEncoder.encode("userpassword"));
            regularUser.setRoles(userRoles);
            usuarioRepository.save(regularUser);
        }
    }
}