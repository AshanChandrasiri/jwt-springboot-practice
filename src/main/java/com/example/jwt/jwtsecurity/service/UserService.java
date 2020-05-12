package com.example.jwt.jwtsecurity.service;

import com.example.jwt.jwtsecurity.security.payload.request.LoginRequest;
import com.example.jwt.jwtsecurity.security.payload.request.SignupRequest;
import com.example.jwt.jwtsecurity.security.payload.response.CurrentAccountResponse;
import com.example.jwt.jwtsecurity.security.payload.response.JwtResponse;
import org.springframework.http.ResponseEntity;

import java.util.Optional;


public interface UserService {

    ResponseEntity<?> registerUser(SignupRequest signUpRequest);

    JwtResponse authenticateUser(LoginRequest loginRequest);

    CurrentAccountResponse currentUser();


}
