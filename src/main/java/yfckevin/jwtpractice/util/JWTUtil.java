package yfckevin.jwtpractice.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Optional;

@Component
public class JWTUtil {

    private String secretKey;
    private int lifeTime;

    // 產生token，將userId簽署到token內，供之後的CRUD用途
    public String sign(String userId){
        return Optional
                .of(new Date())
                .map(v -> Jwts
                        .builder()
                        .setIssuer("jwt-practice")
                        .setAudience(null)
                        .setExpiration(new Date(System.currentTimeMillis() + lifeTime))
                        .setNotBefore(v)
                        .setIssuedAt(v)
                        .setId(userId)
                        .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()), SignatureAlgorithm.HS256)
                        .compact()
                )
                .get();
    }

    // 驗證token，是否帶有合法的userId
    public String verify(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .build()
                .parseClaimsJwt(token)
                .getBody()
                .getId();
    }
}
