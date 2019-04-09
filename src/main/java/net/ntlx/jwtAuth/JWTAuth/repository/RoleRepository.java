package net.ntlx.jwtAuth.JWTAuth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import net.ntlx.jwtAuth.JWTAuth.model.Role;
import net.ntlx.jwtAuth.JWTAuth.model.RoleName;

public interface RoleRepository extends JpaRepository<Role, Long>{
	Optional<Role> findByName(RoleName roleName);
}
