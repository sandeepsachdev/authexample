package com.example.authexample.admin;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.client.HttpClientErrorException;

import com.example.authexample.TestAuth0Config;

@SpringBootTest(properties = {
    "AUTH0_DOMAIN=example.auth0.com",
    "AUTH0_CLIENT_ID=test-client",
    "AUTH0_CLIENT_SECRET=test-secret"
})
@AutoConfigureMockMvc
@Import(TestAuth0Config.class)
class UserAdminControllerTests {

    private static final Auth0Models.Role ADMIN = new Auth0Models.Role("rol_admin", "admin", "Admins");
    private static final Auth0Models.Role MEMBER = new Auth0Models.Role("rol_member", "member", "Members");
    private static final Auth0Models.User ADA =
        new Auth0Models.User("auth0|ada", "ada@example.com", "Ada Lovelace", null, "2026-10-15T09:30:00.000Z", 4, false);

    @Autowired
    MockMvc mvc;

    @MockitoBean
    Auth0ManagementClient auth0;

    @BeforeEach
    void setUp() {
        when(auth0.isConfigured()).thenReturn(true);
        when(auth0.listRoles()).thenReturn(List.of(ADMIN, MEMBER));
    }

    private static RequestPostProcessor admin(String subject) {
        return oidcLogin()
            .idToken(t -> t.subject(subject))
            .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    @Test
    void onlyAdminsCanOpenUserManagement() throws Exception {
        mvc.perform(get("/admin/users").with(oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_MEMBER"))))
            .andExpect(status().isForbidden());
        mvc.perform(post("/admin/users/auth0|ada/roles").param("roleIds", "rol_admin")
                .with(oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_MEMBER"))).with(csrf()))
            .andExpect(status().isForbidden());
        verify(auth0, never()).assignRoles(any(), any());
    }

    @Test
    void listsUsersWithTheirRoles() throws Exception {
        when(auth0.roleMemberIds("rol_admin")).thenReturn(List.of());
        when(auth0.roleMemberIds("rol_member")).thenReturn(List.of("auth0|ada"));
        when(auth0.listUsers(0, UserAdminController.PER_PAGE))
            .thenReturn(new Auth0Models.UserPage(0, 25, 1, List.of(ADA)));

        mvc.perform(get("/admin/users").with(admin("auth0|me")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Ada Lovelace")))
            .andExpect(content().string(containsString(">member<")))
            .andExpect(content().string(containsString("2026-10-15 09:30")))
            .andExpect(content().string(containsString("/admin/users/auth0%7Cada")));
    }

    @Test
    void editPageShowsCheckedRoles() throws Exception {
        when(auth0.getUser("auth0|ada")).thenReturn(ADA);
        when(auth0.getUserRoles("auth0|ada")).thenReturn(List.of(MEMBER));

        mvc.perform(get("/admin/users/{id}", "auth0|ada").with(admin("auth0|me")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("value=\"rol_member\" checked")))
            .andExpect(content().string(containsString("value=\"rol_admin\">")));
    }

    @Test
    void savingRolesAddsAndRemovesTheDifference() throws Exception {
        when(auth0.getUserRoles("auth0|ada")).thenReturn(List.of(MEMBER));

        mvc.perform(post("/admin/users/{id}/roles", "auth0|ada").param("roleIds", "rol_admin")
                .with(admin("auth0|me")).with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/admin/users/auth0%7Cada"))
            .andExpect(flash().attribute("message", containsString("Roles updated")));

        verify(auth0).assignRoles("auth0|ada", List.of("rol_admin"));
        verify(auth0).removeRoles("auth0|ada", List.of("rol_member"));
    }

    @Test
    void uncheckingEverythingRemovesAllRoles() throws Exception {
        when(auth0.getUserRoles("auth0|ada")).thenReturn(List.of(ADMIN, MEMBER));

        mvc.perform(post("/admin/users/{id}/roles", "auth0|ada").with(admin("auth0|me")).with(csrf()))
            .andExpect(status().is3xxRedirection());

        verify(auth0).assignRoles("auth0|ada", List.of());
        verify(auth0).removeRoles("auth0|ada", List.of("rol_admin", "rol_member"));
    }

    @Test
    void adminCannotRemoveOwnAdminRole() throws Exception {
        when(auth0.getUserRoles("auth0|me")).thenReturn(List.of(ADMIN));

        mvc.perform(post("/admin/users/{id}/roles", "auth0|me").param("roleIds", "rol_member")
                .with(admin("auth0|me")).with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(flash().attribute("error", containsString("can't remove your own admin role")));

        verify(auth0, never()).assignRoles(any(), any());
        verify(auth0, never()).removeRoles(any(), any());
    }

    @Test
    void showsSetupInstructionsWhenNotConfigured() throws Exception {
        when(auth0.isConfigured()).thenReturn(false);

        mvc.perform(get("/admin/users").with(admin("auth0|me")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("AUTH0_MGMT_CLIENT_ID")));
    }

    @Test
    void showsAuth0ErrorsInsteadOfFailing() throws Exception {
        when(auth0.listUsers(anyInt(), eq(UserAdminController.PER_PAGE))).thenThrow(HttpClientErrorException.create(
            HttpStatus.FORBIDDEN, "Forbidden", HttpHeaders.EMPTY,
            "{\"message\":\"Insufficient scope, expected any of: read:users\"}".getBytes(StandardCharsets.UTF_8),
            StandardCharsets.UTF_8));

        mvc.perform(get("/admin/users").with(admin("auth0|me")))
            .andExpect(status().isBadGateway())
            .andExpect(content().string(containsString("Insufficient scope")));
    }
}
