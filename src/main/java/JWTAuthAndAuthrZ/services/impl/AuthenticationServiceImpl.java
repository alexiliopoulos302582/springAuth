package JWTAuthAndAuthrZ.services.impl;


import JWTAuthAndAuthrZ.dto.JwtAuthenticationResponse;
import JWTAuthAndAuthrZ.dto.RefreshTokenRequest;
import JWTAuthAndAuthrZ.dto.SignInRequest;
import JWTAuthAndAuthrZ.dto.SignUpRequest;
import JWTAuthAndAuthrZ.entities.Role;
import JWTAuthAndAuthrZ.entities.User;
import JWTAuthAndAuthrZ.repository.UserRepository;
import JWTAuthAndAuthrZ.services.AuthenticationService;
import JWTAuthAndAuthrZ.services.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl      implements AuthenticationService {

    private final UserRepository userRepository;


    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final JWTService jwtService;


    public User signup(SignUpRequest signUpRequest) {
        JWTAuthAndAuthrZ.entities.User user = new JWTAuthAndAuthrZ.entities.User();
        user.setEmail(signUpRequest.getEmail());
        user.setFirstname(signUpRequest.getFirstName());
        user.setSecondname(signUpRequest.getLastName());
    user.setRole(Role.USER);
    user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));

        return userRepository.save(user);

    }


    public JwtAuthenticationResponse signin(SignInRequest signInRequest) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(signInRequest.getEmail(),
                        signInRequest.getPassword())
        );

        var user = userRepository.findByEmail(signInRequest.getEmail()).orElseThrow(()->
                new IllegalArgumentException("invalid email or password")
        );
        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

        JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
        jwtAuthenticationResponse.setToken(jwt);
        jwtAuthenticationResponse.setRefreshToken(refreshToken);
        return jwtAuthenticationResponse;
    }


    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
    String userEmail= jwtService.extractUserName(refreshTokenRequest.getToken());
        User user = userRepository.findByEmail(userEmail).orElseThrow();
        if (jwtService.isTokenValid(refreshTokenRequest.getToken(), user)) {
            var jwt = jwtService.generateToken(user);

            JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
            jwtAuthenticationResponse.setToken(jwt);
            jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());
            return jwtAuthenticationResponse;
        }
        return null;
    }


}
