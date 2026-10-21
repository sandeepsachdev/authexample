package com.example.authexample.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

@Configuration
public class SecurityConfig {

    private final String issuer;
    private final String clientId;
    private final String rolesClaim;

    public SecurityConfig(
            @Value("${spring.security.oauth2.client.provider.auth0.issuer-uri}") String issuer,
            @Value("${spring.security.oauth2.client.registration.auth0.client-id}") String clientId,
            @Value("${app.auth0.roles-claim}") String rolesClaim) {
        this.issuer = issuer;
        this.clientId = clientId;
        this.rolesClaim = rolesClaim;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrations)
            throws Exception {
        http
            // Access levels: public -> any signed-in user -> MEMBER -> ADMIN.
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/css/**", "/error", "/actuator/health/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/members/**").hasRole("MEMBER")
                .anyRequest().authenticated())
            // Redirects unauthenticated users to Auth0's Universal Login page,
            // and maps the Auth0 roles claim to Spring Security roles on the way back.
            // "?mfa" on the login URL requests a fresh login with MFA (step-up authentication).
            .oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(authz -> authz
                    .authorizationRequestResolver(new StepUpAuthorizationRequestResolver(clientRegistrations)))
                .userInfoEndpoint(userInfo -> userInfo.userAuthoritiesMapper(new Auth0RolesMapper(rolesClaim))))
            // Signed-in users without the required role see a friendly 403 page.
            .exceptionHandling(ex -> ex.accessDeniedPage("/access-denied"))
            // Clears the local session, then signs the user out of Auth0 too.
            .logout(logout -> logout.logoutSuccessHandler(auth0LogoutHandler()));
        return http.build();
    }

    /** An admin can do everything a member can, without needing both roles in Auth0. */
    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.withDefaultRolePrefix()
            .role("ADMIN").implies("MEMBER")
            .build();
    }

    /**
     * Auth0 keeps its own session, so after logging out locally we send the browser to
     * Auth0's /v2/logout endpoint, which then returns the user to our home page.
     * The "returnTo" URL must be listed under "Allowed Logout URLs" in the Auth0 dashboard.
     */
    private LogoutSuccessHandler auth0LogoutHandler() {
        return (request, response, authentication) -> {
            String returnTo = ServletUriComponentsBuilder.fromCurrentContextPath().path("/").toUriString();
            String logoutUrl = UriComponentsBuilder.fromUriString(issuer)
                .path("v2/logout")
                .queryParam("client_id", clientId)
                .queryParam("returnTo", returnTo)
                .encode()
                .toUriString();
            response.sendRedirect(logoutUrl);
        };
    }
}
