package com.isra.userauth.repositories;

import com.isra.userauth.domain.Roles;
import com.isra.userauth.domain.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RolesRepository extends JpaRepository<Roles, Long> {
}
