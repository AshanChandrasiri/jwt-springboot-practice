package com.example.jwt.jwtsecurity.repository;

import com.example.jwt.jwtsecurity.model.Role;
import com.example.jwt.jwtsecurity.model.enumeration.ERole;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface RoleRepository extends MongoRepository<Role, String> {
    Optional<Role> findByName(ERole name);
}
