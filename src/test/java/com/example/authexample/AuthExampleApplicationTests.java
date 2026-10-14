package com.example.authexample;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {
    "AUTH0_DOMAIN=example.auth0.com",
    "AUTH0_CLIENT_ID=test-client",
    "AUTH0_CLIENT_SECRET=test-secret"
})
@AutoConfigureMockMvc
class AuthExampleApplicationTests {

    /** Avoids OIDC discovery against a real Auth0 tenant during tests. */
    @TestConfiguration
    static class TestClientRegistrations {
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

    @Autowired
    MockMvc mvc;

    @Test
    void homeIsPublic() throws Exception {
        mvc.perform(get("/"))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Log in with Auth0")));
    }

    @Test
    void healthIsPublic() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void profileRedirectsAnonymousUsersToAuth0() throws Exception {
        mvc.perform(get("/profile"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("http://localhost/oauth2/authorization/auth0"));
    }

    @Test
    void profileShowsClaimsWhenLoggedIn() throws Exception {
        mvc.perform(get("/profile").with(oidcLogin().idToken(t -> t
                .subject("auth0|123")
                .claim("name", "Ada Lovelace")
                .claim("email", "ada@example.com"))))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Ada Lovelace")))
            .andExpect(content().string(containsString("ada@example.com")))
            .andExpect(content().string(containsString("auth0|123")));
    }

    @Test
    void logoutRedirectsToAuth0Logout() throws Exception {
        mvc.perform(post("/logout").with(oidcLogin()).with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl(
                "https://example.auth0.com/v2/logout?client_id=test-client&returnTo=http://localhost/"));
    }
}
