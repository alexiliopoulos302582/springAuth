package JWTAuthAndAuthrZ.services;


import JWTAuthAndAuthrZ.entities.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public interface JWTService {

    String extractUserName(String token);


    String generateToken(UserDetails userDetails);


    public boolean isTokenValid(String token, UserDetails userDetails);

    String generateRefreshToken(Map<String, Object> extraClaims, UserDetails userDetails);
}
