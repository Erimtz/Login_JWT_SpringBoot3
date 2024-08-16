package com.emartinez.demoJwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    private static final String SECRET_KEY = "a0c7d3a1def6e189009c0c4fac45b3f30b0f8c995c74861d8cd9bb6d4331d57a0fbb721db733daa0d3bdcc3408adb7904e4c57fa80450f926b188143bec272c54e309cbaa300df6a354a75d4904a76870959aa91d90ec702bb3faa9191a6c788c7f2a81dc4d7376ea04ad3b093527bf9508dd61aaaf827b9daf5026b25ddb3718643e6299948a4474fed6ef174812e4a0510a18177e69059017556742b0fd829bbb86b47f2f5a0b6c9de98a23db09570d9e465afb6a32e3b7b0b450d216c719a5961e9a0cc131083e273f0a6daebd1d50826d60b3ca15d83ef2dfa4d0809fc665ec7f61b1b91692592722fd7755fc21d9020bfe008b9698d35ae7856b55f6ad6";
    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(), user);
    }

    private String getToken(Map<String,Object> extraClaim, UserDetails user) {
        return Jwts
                .builder()
                .setClaims(extraClaim)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String getUsernameFromToken(String token) {
        return getClaims(token, Claims::getSubject);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private Claims getAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJwt(token)
                .getBody();
    }

    public  <T> T getClaims(String token, Function<Claims,T> claimsResolver) {
        final Claims claims = getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Date getExpiration(String token) {
        return getClaims(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token) {
        return getExpiration(token).before(new Date());
    }
}
