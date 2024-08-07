package com.AureliN.SpringSecurityProject.model;

import com.AureliN.SpringSecurityProject.model.Role;
import com.AureliN.SpringSecurityProject.model.User;
import com.AureliN.SpringSecurityProject.repository.UserRepository;
import com.AureliN.SpringSecurityProject.service.AuthenticationResponse;
import com.AureliN.SpringSecurityProject.service.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final UserRepository repository;

    private final PasswordEncoder passwordEncoder;// Inject PasswordEncoder bean
    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository repository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationResponse register(User request){
        User existingUser = repository.findByUsername(request.getUsername()).orElse(null);
        if (existingUser != null) {
            // Handle username conflict (throw exception or return error message)
            throw new IllegalArgumentException("Username already exists");
        }
        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        // Retrieve role from request (assuming it's a field in the request body)
        String requestedRole = String.valueOf(request.getRole()); // Change "getRole" to match your request field name
        // Validate role (optional)
        if (requestedRole != null) {
            boolean validRole = false;
            for (Role role : Role.values()) {
                if (role.name().equals(requestedRole)) {
                    validRole = true;
                    break;
                }
            }
            if (validRole) {
                user.setRole(Role.valueOf(requestedRole));
            } else {
                // Handle invalid role
                throw new IllegalArgumentException("Invalid role provided");
            }
        } else {
            // Handle missing role
            throw new IllegalArgumentException("Role is required");
        }

        // user.setRole(Role.USER);
        //Try and catch here
        user = repository.save(user);

        //String token = jwtService.generateToken(user);

        //return new AuthenticationResponse(token);
        return new AuthenticationResponse("Registration Successful");
    }

    public AuthenticationResponse authenticate(User request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        User user = repository.findByUsername(request.getUsername()).orElseThrow();
        String token = jwtService.generateToken(user);

        return new AuthenticationResponse(token);
    }
}
