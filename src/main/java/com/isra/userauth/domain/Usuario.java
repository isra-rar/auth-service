package com.isra.userauth.domain;

import jakarta.persistence.*;
import lombok.*;

import java.util.Set;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(exclude = "roles")
@ToString(exclude = "roles")
public class Usuario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String firstName;

    private String lastName;

    private String username;

    private String email;

    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Roles> roles;
}
