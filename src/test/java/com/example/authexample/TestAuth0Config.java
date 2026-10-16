package com.example.authexample;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/** Avoids OIDC discovery against a real Auth0 tenant during tests. */
@TestConfiguration
public class TestAuth0Config {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("auth0")
            .clientId("test-client")
            .clientSecret("test-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .scope("openid", "profile", "email")
            .authorizationUri("https://example.auth0.com/authorize")
            .tokenUri("https://example.auth0.com/oauth/token")
            .jwkSetUri("https://example.auth0.com/.well-known/jwks.json")
            .userInfoUri("https://example.auth0.com/userinfo")
            .userNameAttributeName("sub")
            .build());
    }
}
