package com.jaycabasag.authentication.auth;

import com.jaycabasag.authentication.user.User;
import com.jaycabasag.authentication.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.swing.text.html.Option;
import java.io.IOException;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<?> register(
            @RequestBody RegisterRequest request
    ){
        if(!authenticationService.isValidEmail(request.getEmail())){
            AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse("Invalid email.");
            return ResponseEntity.badRequest().body(errorResponse);
        }
        if (authenticationService.isEmailExists(request.getEmail())){
            AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse("Email already exists.");
            return ResponseEntity.badRequest().body(errorResponse);
        }
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody AuthenticationRequest request
    ){
        if (!authenticationService.isEmailExists(request.getEmail())){
            AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse("Email does not exists.");
            return ResponseEntity.badRequest().body(errorResponse);
        }
        return ResponseEntity.ok(authenticationService.login(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        authenticationService.refreshToken(request, response);
    }

}
