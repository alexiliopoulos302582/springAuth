package JWTAuthAndAuthrZ.services;


import JWTAuthAndAuthrZ.dto.JwtAuthenticationResponse;
import JWTAuthAndAuthrZ.dto.RefreshTokenRequest;
import JWTAuthAndAuthrZ.dto.SignInRequest;
import JWTAuthAndAuthrZ.dto.SignUpRequest;
import JWTAuthAndAuthrZ.entities.User;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

@Component
public interface AuthenticationService          {


    User signup(SignUpRequest signUpRequest);


    JwtAuthenticationResponse signin(SignInRequest signInRequest);


    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
