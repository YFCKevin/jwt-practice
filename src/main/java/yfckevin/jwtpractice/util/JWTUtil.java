package yfckevin.jwtpractice.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Optional;

@Component
public class JWTUtil {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;
    @Value("${application.security.jwt.lifetime}")
    private int lifeTime;

    // 產生token，將userId簽署到token內，供之後的CRUD用途
    public String generateToken(String userEmail){
        return Optional
                .of(new Date())
                .map(v -> Jwts
                        .builder()
                        .setIssuer("jwt-practice")
                        .setAudience(null)
                        .setExpiration(new Date(System.currentTimeMillis() + lifeTime))
                        .setNotBefore(v)
                        // JWT發行時間，代表new Date()
                        .setIssuedAt(v)
                        .setId(userEmail)
                        .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey)), SignatureAlgorithm.HS256)
                        .compact()
                )
                .get();
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String userEmail = verify(token);
        return (userEmail.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        Date expirationDate = Jwts
                .parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .build()
                .parseClaimsJwt(token)
                .getBody()
                .getExpiration();

        return expirationDate.before(new Date());
    }

    // 驗證token，是否帶有合法的userEmail，並取出此userEmail
    public String verify(String token){
        return Jwts
                .parserBuilder()
                // signing key主要用來驗證
                .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey)))
                .build()
                .parseClaimsJwt(token)
                // 取出all claims
                .getBody()
                .getId();
    }
}
