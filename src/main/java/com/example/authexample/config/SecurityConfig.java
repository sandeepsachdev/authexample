package com.example.authexample.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

@Configuration
public class SecurityConfig {

    private final String issuer;
    private final String clientId;

    public SecurityConfig(
            @Value("${spring.security.oauth2.client.provider.auth0.issuer-uri}") String issuer,
            @Value("${spring.security.oauth2.client.registration.auth0.client-id}") String clientId) {
        this.issuer = issuer;
        this.clientId = clientId;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/css/**", "/error", "/actuator/health/**").permitAll()
                .anyRequest().authenticated())
            // Redirects unauthenticated users to Auth0's Universal Login page.
            .oauth2Login(Customizer.withDefaults())
            // Clears the local session, then signs the user out of Auth0 too.
            .logout(logout -> logout.logoutSuccessHandler(auth0LogoutHandler()));
        return http.build();
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
