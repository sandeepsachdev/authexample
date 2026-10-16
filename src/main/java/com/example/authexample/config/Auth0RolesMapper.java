package com.example.authexample.config;

import java.util.Collection;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

/**
 * Turns the Auth0 roles in the ID token into Spring Security roles.
 *
 * Auth0 doesn't put roles in tokens by default; a Post-Login Action (see
 * auth0/add-roles-to-tokens.js) adds them under a custom claim such as
 * "https://authexample.demo/roles": ["admin"]. Each role becomes ROLE_ADMIN etc.,
 * so it can be checked with hasRole("ADMIN").
 */
public class Auth0RolesMapper implements GrantedAuthoritiesMapper {

    private final String rolesClaim;

    public Auth0RolesMapper(String rolesClaim) {
        this.rolesClaim = rolesClaim;
    }

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Set<GrantedAuthority> mapped = new HashSet<>(authorities);
        for (GrantedAuthority authority : authorities) {
            if (authority instanceof OidcUserAuthority oidc) {
                Object roles = oidc.getIdToken().getClaims().get(rolesClaim);
                if (roles instanceof Collection<?> names) {
                    for (Object name : names) {
                        mapped.add(new SimpleGrantedAuthority("ROLE_" + name.toString().trim().toUpperCase(Locale.ROOT)));
                    }
                }
            }
        }
        return mapped;
    }
}
