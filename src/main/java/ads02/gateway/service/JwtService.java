package ads02.gateway.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class JwtService {

    private Key accessKey;

    public JwtService(@Value("${jwt.secret.access}") String JWT_ACCESS_SECRET_KEY) {
        this.accessKey = Keys.hmacShaKeyFor(JWT_ACCESS_SECRET_KEY.getBytes());
    }

    public Claims getAllClaimsFromToken(String token){
        return Jwts.parserBuilder().setSigningKey(accessKey).build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getClaimFromJwt(String claim, String token) {
        return getAllClaimsFromToken(token).get(claim, String.class);
    }

    public boolean isValid(String token) {
        return getAllClaimsFromToken(token).getExpiration().before(new Date());
    }
}
