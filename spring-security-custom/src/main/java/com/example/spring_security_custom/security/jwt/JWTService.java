package com.example.spring_security_custom.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
@Service
public class JWTService {

    @Value("${security.token.access.secret-key}")
    private  String ACCESS_TOKEN_SECRET_KEY;

    @Value("${security.token.refresh.secret-key}")
    private  String REFRESH_TOKEN_SECRET_KEY;

    @Value("${security.token.access.time}")
    private  long ACCESS_TOKEN_EXPIRATION_TIME;

    @Value("${security.token.refresh.time}")
    private  long REFRESH_TOKEN_EXPIRATION_TIME;


    private String generateToken(Map<String, Object> extraClaims, String username, long expirationTime, Key key) {
        String token = Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
        log.info("Generated token for username: {}", username);
        log.debug("Token: {}", token);
        return token;
    }

    public String generateAccessToken(String username) {
        log.info("Generating access token for username: {}", username);
        return generateToken(new HashMap<>(), username, ACCESS_TOKEN_EXPIRATION_TIME, getAccessTokenSignInKey());
    }

    public String generateRefreshToken(String username) {
        log.info("Generating refresh token for username: {}", username);
        return generateToken(new HashMap<>(), username, REFRESH_TOKEN_EXPIRATION_TIME, getRefreshTokenSignInKey());
    }

    public String extractAccessTokenUsername(String accessToken) {
        log.info("Extracting username from access token");
        return extractClaim(accessToken, Claims::getSubject, getAccessTokenSignInKey());
    }

    public String extractRefreshTokenUsername(String refreshToken) {
        log.info("Extracting username from refresh token");
        return extractClaim(refreshToken, Claims::getSubject, getRefreshTokenSignInKey());
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver, Key key) {
        final Claims claims = extractAllClaims(token, key);
        log.debug("Extracted claims: {}", claims);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token, Key key) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        log.debug("Extracted all claims: {}", claims);
        return claims;
    }

    public boolean isTokenExpired(String token) {
        DecodedJWT decodedJWT = JWT.decode(token);
        Date expiresAt = decodedJWT.getExpiresAt();
        boolean isExpired = expiresAt.before(new Date());
        log.info("Token expired: {}", isExpired);
        return isExpired;
    }

    public String getTokenExpiredMessage(String token) {
        DecodedJWT decodedJWT = JWT.decode(token);
        Date expiresAt = decodedJWT.getExpiresAt();
        String message = "JWT expired at " + expiresAt + ". Current time " + new Date();
        log.warn(message);
        return message;
    }

    private Key getAccessTokenSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(ACCESS_TOKEN_SECRET_KEY);
        Key key = Keys.hmacShaKeyFor(keyBytes);
        log.debug("Access token signing key: {}", key);
        return key;
    }

    private Key getRefreshTokenSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(REFRESH_TOKEN_SECRET_KEY);
        Key key = Keys.hmacShaKeyFor(keyBytes);
        log.debug("Refresh token signing key: {}", key);
        return key;
    }

}
