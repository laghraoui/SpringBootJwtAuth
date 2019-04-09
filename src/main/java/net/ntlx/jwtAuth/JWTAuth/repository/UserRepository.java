package net.ntlx.jwtAuth.JWTAuth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import net.ntlx.jwtAuth.JWTAuth.model.User;

public interface UserRepository extends JpaRepository<User, Long>{
	
	Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
    
}
