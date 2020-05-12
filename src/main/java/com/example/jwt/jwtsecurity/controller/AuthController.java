package com.example.jwt.jwtsecurity.controller;

import com.example.jwt.jwtsecurity.repository.UserRepository;
import com.example.jwt.jwtsecurity.security.payload.request.LoginRequest;
import com.example.jwt.jwtsecurity.security.payload.request.SignupRequest;
import com.example.jwt.jwtsecurity.security.payload.response.CurrentAccountResponse;
import com.example.jwt.jwtsecurity.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {


    @Autowired
    UserService userService;


    @Autowired
    UserRepository userRepository;


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok().body(userService.authenticateUser(loginRequest));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        return userService.registerUser(signUpRequest);
    }

    @GetMapping("/account")
    public ResponseEntity<?> currentAccount1(){
        return  ResponseEntity.ok().body(userService.currentUser());
    }

}

