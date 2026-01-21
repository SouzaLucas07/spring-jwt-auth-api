package com.example.JWT.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
@Component
public class SecurityConfig {

    @Value("${security.config.key}")
    private String key;

    @Value("${security.config.prefix}")
    private String prefix;

    @Value("${security.config.expiration}")
    private long expiration;

    // getters
    public String getKey() { return key; }
    public String getPrefix() { return prefix; }
    public long getExpiration() { return expiration; }
}
