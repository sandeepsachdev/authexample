package com.example.authexample;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {
    "AUTH0_DOMAIN=example.auth0.com",
    "AUTH0_CLIENT_ID=test-client",
    "AUTH0_CLIENT_SECRET=test-secret"
})
@AutoConfigureMockMvc
@Import(TestAuth0Config.class)
class AuthExampleApplicationTests {

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

    @Test
    void membersAndAdminRedirectAnonymousUsersToLogin() throws Exception {
        mvc.perform(get("/members")).andExpect(status().is3xxRedirection());
        mvc.perform(get("/admin")).andExpect(status().is3xxRedirection());
    }

    @Test
    void userWithoutRolesIsDeniedMembersAndAdmin() throws Exception {
        mvc.perform(get("/members").with(oidcLogin()))
            .andExpect(status().isForbidden())
            .andExpect(forwardedUrl("/access-denied"));
        mvc.perform(get("/admin").with(oidcLogin()))
            .andExpect(status().isForbidden());
    }

    @Test
    void memberCanOpenMembersButNotAdmin() throws Exception {
        var member = oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_MEMBER"));
        mvc.perform(get("/members").with(member))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Members area")));
        mvc.perform(get("/admin").with(member))
            .andExpect(status().isForbidden());
    }

    @Test
    void adminCanOpenAdminAndMembersThroughRoleHierarchy() throws Exception {
        var admin = oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
        mvc.perform(get("/admin").with(admin))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Admin area")));
        mvc.perform(get("/members").with(admin))
            .andExpect(status().isOk());
    }

    @Test
    void profileListsRolesAndAccess() throws Exception {
        mvc.perform(get("/profile").with(oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString(">ADMIN<")))
            // Hierarchy applies in templates too: an admin sees the Members area as open.
            .andExpect(content().string(org.hamcrest.Matchers.not(containsString("needs the <code>member</code>"))));
    }
}
