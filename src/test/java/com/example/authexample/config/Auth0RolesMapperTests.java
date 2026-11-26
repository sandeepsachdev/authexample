package com.example.authexample.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

class Auth0RolesMapperTests {

    private static final String CLAIM = "https://authexample.demo/roles";

    private final Auth0RolesMapper mapper = new Auth0RolesMapper(CLAIM);

    @Test
    void mapsRolesClaimToSpringRoles() {
        var authorities = mapper.mapAuthorities(List.of(authorityWithClaims(Map.of(CLAIM, List.of("admin", "Member")))));

        assertThat(authorities).extracting(GrantedAuthority::getAuthority)
            .contains("ROLE_ADMIN", "ROLE_MEMBER", "OIDC_USER");
    }

    @Test
    void grantsNoRolesWhenClaimIsMissing() {
        var authorities = mapper.mapAuthorities(List.of(authorityWithClaims(Map.of())));

        assertThat(authorities).extracting(GrantedAuthority::getAuthority)
            .noneMatch(a -> a.startsWith("ROLE_"));
    }

    private static OidcUserAuthority authorityWithClaims(Map<String, Object> extraClaims) {
        var token = OidcIdToken.withTokenValue("token")
            .subject("auth0|123")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(60))
            .claims(c -> c.putAll(extraClaims))
            .build();
        return new OidcUserAuthority(token);
    }
}
