package com.example.JWT.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JWTCreator {

    private final SecurityConfig securityConfig;
    private final SecretKey secretKey;

    // Construtor com injeção do SecurityConfig
    public JWTCreator(SecurityConfig securityConfig) {
        this.securityConfig = securityConfig;

        // Garante que a chave tenha tamanho suficiente para HS512 (>= 64 bytes)
        if (securityConfig.getKey() == null || securityConfig.getKey().getBytes(StandardCharsets.UTF_8).length < 64) {
            throw new IllegalArgumentException(
                    "A chave JWT é muito curta! Para HS512, use pelo menos 64 caracteres."
            );
        }

        this.secretKey = Keys.hmacShaKeyFor(securityConfig.getKey().getBytes(StandardCharsets.UTF_8));
    }

    // Gera token JWT com prefixo
    public String generateToken(JWTObject jwtObject) {
        String token = Jwts.builder()
                .setSubject(jwtObject.getSubject())
                .setIssuedAt(jwtObject.getIssuedAt())
                .setExpiration(jwtObject.getExpiration())
                .claim("authorities", normalizeRoles(jwtObject.getRoles()))
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .compact();
        return securityConfig.getPrefix() + " " + token;
    }

    // Faz parsing do token JWT e retorna JWTObject
    public JWTObject parseToken(String token) {
        if (token.startsWith(securityConfig.getPrefix() + " ")) {
            token = token.substring((securityConfig.getPrefix() + " ").length());
        }

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        JWTObject object = new JWTObject();
        object.setSubject(claims.getSubject());
        object.setIssuedAt(claims.getIssuedAt());
        object.setExpiration(claims.getExpiration());
        object.setRoles(((List<?>) claims.get("authorities")).stream()
                .map(Object::toString)
                .collect(Collectors.toList()));

        return object;
    }

    // Normaliza roles para o padrão ROLE_X
    private List<String> normalizeRoles(List<String> roles) {
        return roles.stream()
                .map(r -> "ROLE_" + r.replace("ROLE_", ""))
                .collect(Collectors.toList());
    }
}
